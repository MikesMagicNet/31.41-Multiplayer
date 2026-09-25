"""Find every native RVA / vtable index the gameserver needs from a flat dump of the 31.41 client,
then write them (with byte signatures for runtime verification) to ../Polonium/Offsets.h.

    py find_offsets.py            # uses pe.DEFAULT_DUMP
    py find_offsets.py --dump X   # explicit dump
    py find_offsets.py --check    # only print, do not write Offsets.h

Each finder below explains how the offset is derived so it can be redone on a new build.
"""
import argparse, collections, os, re, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe import Image
from scan import Scanner, ClassInfo, disasm, log_record_funcs, rip_target
import netmode

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Polonium", "Offsets.h")


class Finder:
    def __init__(self, img):
        self.img = img
        self.sc = Scanner(img)
        self.rvas = {}      # name -> (rva, how)
        self.idx = {}       # name -> (index, how)
        self.globals = {}   # name -> (rva, how)
        self.errors = []
        self._classes = {}
        self.patches = []   # (rva, old bytes, new bytes, note)

    def cls(self, name):
        if name not in self._classes:
            self._classes[name] = ClassInfo(self.sc, name)
        return self._classes[name]

    def rva(self, name, value, how):
        if value is None:
            self.errors.append(name)
        self.rvas[name] = (value, how)
        return value

    def index(self, name, value, how):
        if value is None:
            self.errors.append(name)
        self.idx[name] = (value, how)
        return value

    # ---- helpers ----
    def exec_thunk(self, func_name):
        """Native RPC/BlueprintNativeEvent thunk from the StaticRegisterNatives {name, exec} table.
        The Verse duplicates of the table have no vcall, so require one."""
        img, sc = self.img, self.sc
        for srva in img.find_ascii_exact(func_name, sec=".rdata"):
            for p in img.find_all(struct.pack("<Q", img.image_base + srva), sec=".rdata"):
                fn = img.u64(p + 8) - img.image_base
                if sc.text_lo <= fn < sc.text_hi:
                    b = img.func_bounds(fn)
                    if b and self._vcalls(img.read(b[0], b[1] - b[0])):
                        return fn
        return None

    @staticmethod
    def _vcalls(code):
        found = []
        for i in range(len(code) - 6):
            if code[i] == 0xFF and code[i + 1] in (0x90, 0x91, 0x92, 0x93):
                found.append(struct.unpack_from("<I", code, i + 2)[0] // 8)
            elif code[i] == 0xFF and code[i + 1] in (0x50, 0x51, 0x52, 0x53):
                found.append(code[i + 2] // 8)
            elif code[i] == 0x48 and code[i + 1] == 0x8B and (code[i + 2] & 0xC7) == 0x80:
                # `mov reg,[rax+disp32]` then `call reg` (big RPC thunks); only real vtable-sized displacements
                disp = struct.unpack_from("<I", code, i + 3)[0]
                if 0x800 <= disp < 0x4000:
                    found.append(disp // 8)
        return found

    def thunk_vcall_index(self, func_name, which=-1):
        """vtable index the exec thunk calls through (last call = _Implementation)."""
        fn = self.exec_thunk(func_name)
        if fn is None:
            return None
        s, e = self.img.func_bounds(fn)
        found = self._vcalls(self.img.read(s, e - s))
        return found[which] if found else None

    def only_func(self, funcs, what):
        funcs = list(funcs)
        if len(funcs) != 1:
            print("  ! %s: expected one function, got %s" % (what, ["0x%X" % f for f in funcs]))
            return funcs[0] if funcs else None
        return funcs[0]

    # ---- signature for runtime verification ----
    def signature(self, rva, length=24):
        """IDA-style sig of the first bytes; rip-relative displacements and rel32/rel8 branch targets wildcarded.
        The first byte is wildcarded too so a dump taken from a patched process (ret at function start) still matches."""
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        code = self.img.read(rva, length + 16)
        out = []
        n = 0
        for x in md.disasm(code, self.img.image_base + rva):
            if n >= length:
                break
            raw = code[n:n + x.size]
            mask = [False] * x.size
            if "rip" in x.op_str and x.disp_size:
                for j in range(x.disp_offset, x.disp_offset + x.disp_size):
                    mask[j] = True
            if x.mnemonic in ("call", "jmp") or x.mnemonic.startswith("j") or x.mnemonic.startswith("loop"):
                if x.imm_size:
                    for j in range(x.imm_offset, x.imm_offset + x.imm_size):
                        mask[j] = True
            for b, m in zip(raw, mask):
                out.append("?" if m else "%02X" % b)
            n += x.size
        out[0] = "?"
        return " ".join(out)

    # ---- the finders ----
    def run(self):
        img, sc = self.img, self.sc

        # FName::FName(const TCHAR*, EFindName): by far the most common call preceded by `mov r8d, 1` (FNAME_Add).
        cnt = collections.Counter()
        t, base = sc.text, sc.text_lo
        for m in re.finditer(rb"\x41\xB8\x01\x00\x00\x00", t):
            i = m.end()
            for j in range(i, i + 16):
                if t[j] == 0xE8:
                    tgt = base + j + 5 + struct.unpack_from("<i", t, j + 1)[0]
                    if sc.text_lo <= tgt < sc.text_hi:
                        cnt[tgt] += 1
                    break
        self.rva("FNameCtor", cnt.most_common(1)[0][0], "most common call after `mov r8d,1` (FNAME_Add)")

        # StaticLoadObject: the function that logs '...StaticLoadObjectInternal %s' is StaticLoadObjectInternal; its non-recursive caller is StaticLoadObject.
        internal = self.only_func(log_record_funcs(sc, "StaticLoadObjectInternal"), "StaticLoadObjectInternal")
        callers = {img.func_start(c) for c in sc.callers(internal)} - {internal}
        self.rva("StaticLoadObject", self.only_func(callers, "StaticLoadObject"), "caller of StaticLoadObjectInternal (log string)")

        # UWorld::AttemptDeriveFromURL: references L"listen" and has ~1000 callers (inlined GetNetMode fallback).
        cands = [(f, len(sc.callers(f))) for f in sc.funcs_referencing("listen")]
        cands.sort(key=lambda x: -x[1])
        adfu = self.rva("AttemptDeriveFromURL", cands[0][0] if cands else None, "function referencing L\"listen\" with the most callers")

        # GIsClient: read right after the IsServer() vcall in an inlined GetNetMode site (`mov al,[rip+X]; neg; sbb; neg; inc`).
        gisclient = None
        for c in sc.callers(adfu)[:400]:
            ins = disasm(img, img.func_start(c))
            for i, x in enumerate(ins[:-4]):
                if x.mnemonic == "mov" and x.op_str.startswith("al, byte ptr [rip") and ins[i + 1].mnemonic == "neg" and ins[i + 2].mnemonic == "sbb":
                    gisclient = rip_target(img, x)
                    break
            if gisclient:
                break
        self.globals["GIsClient"] = (gisclient, "byte read before neg/sbb/neg/inc in inlined GetNetMode")
        # GIsServer: one of the two globals saved/cleared/restored next to GIsClient (TGuardValue block, fn 0x278F9F0),
        # the one with ~34 readers. Picked by hand, so only "probable".
        self.globals["GIsServer"] = (0x12098945, "manual: sibling of GIsClient in the guard block, few readers (probable)")
        # GMalloc: the first global FMemory::Free (the most-called function in .text) reads. Realloc is its vtable slot 7 (+0x38):
        # FExec's 4 slots, then Malloc 0x28, TryMalloc, Realloc 0x38, TryRealloc, Free 0x48, ..., QuantizeSize 0x60.
        sc.callers(0)
        free_fn = max(sc._call_index, key=lambda f: len(sc._call_index[f]))
        gm = next((rip_target(img, x) for x in disasm(img, free_fn, n=0x40) if x.mnemonic == "mov" and "[rip" in x.op_str), None)
        self.globals["GMalloc"] = (gm, "first global read by FMemory::Free (most-called function); Realloc = vtable slot 7")

        # UNetDriver / UIpNetDriver vtables from their class registration (GetPrivateStaticClassBody -> InternalConstructor -> ctor -> lea vtable)
        nd, ip = self.cls("UNetDriver"), self.cls("UIpNetDriver")
        ndvt = sc.read_vtable(nd.vtable, 160)
        # TickFlush: references STAT_NetTickFlush and sits in the vtable
        tf = [f for f in sc.funcs_referencing("STAT_NetTickFlush", exact=True) if sc.vtable_index(nd.vtable, f) is not None]
        tickflush = self.only_func(tf, "TickFlush")
        self.index("NetDriver_TickFlush", sc.vtable_index(nd.vtable, tickflush), "UNetDriver vtable slot of the STAT_NetTickFlush function")
        self.rva("NetDriver_TickFlush", tickflush, "STAT_NetTickFlush")
        # UpdateIrisReplicationViews: called from TickFlush, references its STAT string
        uirv = self.only_func(sc.funcs_referencing("STAT_UpdateIrisReplicationViews", exact=True), "UpdateIrisReplicationViews")
        self.rva("UpdateIrisReplicationViews", uirv, "STAT_UpdateIrisReplicationViews")
        # PreSendUpdate: the call right after the UpdateIrisReplicationViews call (client-side Iris path in TickFlush's cold chunk),
        # on [NetDriver+ReplicationSystem]
        presend, repsys_off = None, None
        for site in sc.callers(uirv):
            for x in disasm(img, site + 5, n=0x30):
                if x.mnemonic == "mov" and re.match(r"rcx, qword ptr \[r\w+ \+ 0x[0-9a-f]+\]", x.op_str):
                    repsys_off = int(x.op_str.split("+ ")[1].rstrip("]"), 16)
                if x.mnemonic == "call" and x.op_str.startswith("0x"):
                    presend = int(x.op_str, 16) - img.image_base
                    break
            if presend:
                break
        self.rva("ReplicationSystem_PreSendUpdate", presend, "call following UpdateIrisReplicationViews in TickFlush")
        self.globals["NetDriver_ReplicationSystem"] = (repsys_off, "rcx load before the PreSendUpdate call")
        # InitListen: logs 'listening on port', lives in the UIpNetDriver vtable
        il = [f for f in log_record_funcs(sc, "listening on port") if sc.vtable_index(ip.vtable, f) is not None]
        self.index("NetDriver_InitListen", sc.vtable_index(ip.vtable, self.only_func(il, "InitListen")), "UIpNetDriver slot of the 'listening on port' function")
        # IsServer: slot whose body is `cmp [rcx+ServerConnection],0; sete al; ret`
        isserver = None
        for i, f in enumerate(ndvt):
            ins = disasm(img, f, n=16, count=3)
            if len(ins) == 3 and ins[0].mnemonic == "cmp" and "0xf0]" in ins[0].op_str and ins[1].mnemonic == "sete":
                isserver = i
                break
        self.index("NetDriver_IsServer", isserver, "slot comparing ServerConnection (+0xF0) to 0")
        # SetWorld: only slot touching both World (+0x1A8) and WorldPackage (+0x1B0)
        setworld = None
        for i, f in enumerate(ndvt):
            b = img.func_bounds(f)
            if not b:
                continue
            code = img.read(b[0], b[1] - b[0])
            if b"\xA8\x01\x00\x00" in code and b"\xB0\x01\x00\x00" in code:
                setworld = i
                break
        self.index("NetDriver_SetWorld", setworld, "slot referencing both World and WorldPackage")

        # Game mode virtuals: exec thunks of the BlueprintNativeEvents call the _Implementation through the vtable.
        for fn in ("ReadyToStartMatch", "SpawnDefaultPawnFor", "HandleStartingNewPlayer"):
            self.index("GameMode_" + fn, self.thunk_vcall_index(fn), "vcall in exec%s thunk" % fn)
        # GetGameSessionClass: AFortGameMode's slot that calls AFortGameSession::StaticClass (AGameModeBase::GetGameSessionClass returns a class).
        fgm = self.cls("AFortGameMode")
        fgs = self.cls("AFortGameSession")
        ggsc = None
        for c in sc.callers(fgs.static_class_fn):
            f = img.func_start(c)
            i = sc.vtable_index(fgm.vtable, f)
            if i is not None and i < sc.vtable_len(fgm.vtable) and img.func_bounds(f)[1] - f < 0x60:
                ggsc = i
                break
        self.index("GameMode_GetGameSessionClass", ggsc, "AFortGameMode slot returning AFortGameSession::StaticClass()")
        # HandleMatchHasStarted: plain virtual; AFortGameModeAthena's override logs "AFortGameModeAthena::HandleMatchHasStarted".
        gma = self.cls("AFortGameModeAthena")
        hmhs = [f for f in log_record_funcs(sc, "AFortGameModeAthena::HandleMatchHasStarted") if sc.vtable_index(gma.vtable, f) is not None]
        self.index("GameMode_HandleMatchHasStarted", sc.vtable_index(gma.vtable, self.only_func(hmhs, "HandleMatchHasStarted")), "AFortGameModeAthena slot of the function logging its own name")
        # PlayerController RPC
        self.index("PC_ServerAcknowledgePossession", self.thunk_vcall_index("ServerAcknowledgePossession"), "last vcall in the exec thunk (Validate then Implementation)")
        # UAbilitySystemComponent::InternalServerTryActivateAbility: the vtable slot ServerTryActivateAbility_Implementation
        # calls through. In the client build every ASC class points that slot at an empty `ret` shared with other stubs,
        # so client-activated abilities (pickaxe, emotes) never run server-side. Rebuilt in Abilities.h, as Remix does.
        isa = None
        asc_vt = self.cls("UAbilitySystemComponent").vtable
        impl_slot = self.thunk_vcall_index("ServerTryActivateAbility")
        if asc_vt and impl_slot is not None:
            impl = img.u64(asc_vt + impl_slot * 8) - img.image_base
            found = self._vcalls(img.read(impl, 0x20))
            isa = found[0] if found else None
        self.index("ASC_InternalServerTryActivateAbility", isa, "slot ServerTryActivateAbility_Implementation calls (a ret stub, replaced)")
        self.index("Aircraft_ServerAttemptAircraftJump", self.thunk_vcall_index("ServerAttemptAircraftJump"), "last vcall in the exec thunk (UFortControllerComponent_Aircraft)")
        # AFortPlayerPawn::ServerHandlePickupInfo_Implementation (ret stub on the Athena pawn) and AFortPickup::GivePickupTo
        # (hides/destroys the pickup, item hand-over stripped); GivePickupToPawn's thunk ends in the GivePickupTo vcall.
        self.index("Pawn_ServerHandlePickupInfo", self.thunk_vcall_index("ServerHandlePickupInfo"), "last vcall in the exec thunk (AFortPlayerPawn)")
        self.index("Pickup_GivePickupTo", self.thunk_vcall_index("GivePickupToPawn"), "last vcall in the GivePickupToPawn exec thunk")
        # Building / editing RPCs on AFortPlayerController: Begin/End/Material/Edit are ret stubs, Create only resolves the
        # class data. Create and Edit thunks dispatch through `mov rbx,[rax+disp]; call rbx`.
        for n in ("ServerCreateBuildingActor", "ServerEditBuildingActor", "ServerBeginEditingBuildingActor", "ServerEndEditingBuildingActor", "ServerOnMaterialSelection",
                  "ServerAttemptInventoryDrop"):
            self.index("PC_" + n, self.thunk_vcall_index(n), "last vcall in the exec thunk (AFortPlayerController)")
        # IFortInventoryOwnerInterface::RemoveInventoryItem: ServerRemoveInventoryItem_Implementation forwards to it
        # (`add rcx,<iface>; call [r10+X]`); the controller's own slot returns false on the server.
        rii = None
        sri = self.thunk_vcall_index("ServerRemoveInventoryItem")
        pcv = self.cls("AFortPlayerControllerAthena").vtable
        if sri is not None and pcv:
            impl = img.u64(pcv + sri * 8) - img.image_base
            b = img.func_bounds(impl)
            v = self._vcalls(img.read(b[0], b[1] - b[0])) if b else []
            rii = v[-1] if v else None
        self.index("InvOwner_RemoveInventoryItem", rii, "vcall in ServerRemoveInventoryItem_Implementation (inventory owner interface)")
        # APlayerController level visibility RPCs: the client asks before making a streamed cell visible (making-visible
        # transactions) and shows HLODs until the server acks.
        # Both RPCs end up in UNetConnection::UpdateLevelVisibilityInternal(Connection, const FUpdateLevelVisibilityLevelInfo&),
        # the function logging '...but level is not visible on server.' Hooked there.
        self.rva("UpdateLevelVisibility", self.only_func(log_record_funcs(sc, "but level is not visible on server"), "UpdateLevelVisibility"), "'but level is not visible on server' log (hooked, making-visible requests acked)")
        self.index("PC_ServerPlayEmoteItem", self.thunk_vcall_index("ServerPlayEmoteItem"), "last vcall in the exec thunk")
        self.index("PC_ServerExecuteInventoryItem", self.thunk_vcall_index("ServerExecuteInventoryItem"), "last vcall in the exec thunk (impl is a ret stub in the client build)")

        # Fortnite natives with log strings
        self.rva("ApplyCharacterCustomization", self.only_func(log_record_funcs(sc, "AFortPlayerState::ApplyCharacterCustomization - Failed initialization"), "ApplyCharacterCustomization"), "log string")
        self.rva("InitializePlayerGameplayAbilities", self.only_func(log_record_funcs(sc, "InitializePlayerGameplayAbilities with invalid PlayerStateOrProxy"), "InitializePlayerGameplayAbilities"), "log string")
        # FGenericPlatformMisc::RequestExit: logs 'FPlatformMisc::RequestExit(%i, %s)', the variant with the most callers
        re_c = sorted(((f, len(sc.callers(f))) for f in log_record_funcs(sc, "FPlatformMisc::RequestExit(")), key=lambda x: -x[1])
        self.rva("RequestExit", re_c[0][0] if re_c else None, "'FPlatformMisc::RequestExit(' log, most callers")
        # Unsafe environment popup: references L"UnsafeEnvironment_Title"
        self.rva("UnsafeEnvironment", self.only_func(sc.funcs_referencing("UnsafeEnvironment_Title", exact=True), "UnsafeEnvironment"), "L\"UnsafeEnvironment_Title\"")

        # Game session id change handler: derefs a null interface on the client build when the map opens (Remix's
        # "ChangeGameSessionID crash"). Patched to ret.
        cgs = self.rva("ChangeGameSessionID", self.only_func(sc.funcs_referencing("Core.GameSessionIDChanged", exact=True), "ChangeGameSessionID"), "L\"Core.GameSessionIDChanged\"")
        # its sibling (same null deref through [this][0]->vtable[10]) is the next function in .text and is called right after it
        nxt = img.func_bounds(cgs)[1]
        while img.u8(nxt) == 0xCC: nxt += 1
        self.rva("ChangeGameSessionID2", nxt, "function following ChangeGameSessionID, called right after it")

        # UFortWeaponSoundLibraryComponent::BeginPlay: behind `cmp byte [Fort.Rollback.EnableWeaponMetaSoundParameterPack],1; jne`
        # it binds to WeaponActor (+0x200), null on the server, so equipping crashed. The cvar is forced to 1 by config and the
        # console can't change it in shipping, so the jne becomes a jmp. Its unbind twin null-checks WeaponActor after the gate.
        gate = []
        for f in sc.funcs_referencing("&ThisClass::OnRateOfFireChanged"):
            s_, e_ = img.func_bounds(f)
            code = img.read(s_, e_ - s_)
            for i in range(len(code) - 24):
                if code[i:i + 2] == b"\x80\x3D" and code[i + 6] == 1 and code[i + 7:i + 9] == b"\x0F\x85" and b"\x48\x85\xC0" not in code[i + 13:i + 24]:
                    gate.append(s_ + i + 7)
        self.rva("WeaponSoundGate", gate[0] if len(gate) == 1 else None, "jne after the EnableWeaponMetaSoundParameterPack check in the sound component's BeginPlay (patched to jmp)")

        # Fort.Cosmetics.LoadoutSubsystem.BlockMcpPresetsWhenUsingLockerService: SetPresetMap_FromMcp throws away the
        # loadout from the player's athena profile when this is on (31.41 wants the Locker Service, whose server-side fetch is
        # stripped). The pointer to its value is the `mov rax,[rip+X]; cmp byte [rax],0` just before the 'rejecting' log.
        blk = None
        for helper in log_record_funcs(sc, "rejecting preset map from MCP because"):
            for c in sc.callers(helper):
                f = img.func_start(c)
                ins = disasm(img, f, c - f)
                for i in range(len(ins) - 1):
                    if ins[i].mnemonic == "mov" and ins[i].op_str.startswith("rax, qword ptr [rip") and ins[i + 1].op_str == "byte ptr [rax], 0":
                        blk = rip_target(img, ins[i])
        self.globals["BlockMcpPresetsCVar"] = (blk, "pointer to the cvar's bool, read before the 'rejecting preset map from MCP' log")

        # UGameplayAbility::CanActivateAbility: logs 'could not be activated due to Cooldown' (and Cost, tags, blueprint override).
        # Refuses the melee ability server-side on this build, so hits never land (Remix patches it to return true).
        self.rva("CanActivateAbility", self.only_func(log_record_funcs(sc, "could not be activated due to Cooldown"), "CanActivateAbility"), "'could not be activated due to Cooldown' log (hooked, refusals logged and allowed)")

        # UAbilitySystemComponent::InternalTryActivateAbility: logs 'InternalTryActivateAbility called with invalid Ability'.
        # Hooked for diagnostics: the server never consumes the pickaxe's target data, so failed activations are logged.
        self.rva("InternalTryActivateAbility", self.only_func(log_record_funcs(sc, "InternalTryActivateAbility called with invalid Ability"), "InternalTryActivateAbility"), "'InternalTryActivateAbility called with invalid Ability' log (hooked, failures logged)")

        # AActor::ProcessEvent: AActor's vtable slot 79 (ProcessEvent, SDK ProcessEventIdx 0x4F). It returns before calling
        # UObject::ProcessEvent when the function is neither native nor has Blueprint bytecode, which is how the damage code
        # fires OnDamageServer on most buildings, so the harvest hook has to sit here.
        avt = self.cls("AActor").vtable
        self.rva("ActorProcessEvent", img.u64(avt + 79 * 8) - img.image_base if avt else None, "AActor vtable slot 79 (hooked for OnDamageServer)")

        # UFortBattlePassResourcesWidgetBase resource refresh (vtable slot 153): walks EntryBox_ResourceCounters (+0x2E0), a
        # BindWidget the host never builds. A ticker calls it during the map load and it read null+0x1B0. Patched to ret.
        bp = img.find_all(bytes.fromhex("48895C2408574883EC30488B89E0020000488D542420E8"), sec=".text")
        self.rva("BattlePassResourcesRefresh", bp[0] if len(bp) == 1 else None, "`mov rcx,[rcx+0x2E0]` (EntryBox_ResourceCounters) prologue, unique (patched to ret)")

        # FWeakObjectPtr::operator=(const UObject*): logs 'UObject serial numbers overflowed' and has thousands of callers.
        # Allocates the object's serial number when it has none, which a weak pointer needs to resolve (fresh actors).
        wk = sorted(((len(sc.callers(f)), f) for f in log_record_funcs(sc, "UObject serial numbers overflowed")), reverse=True)
        self.rva("WeakObjectPtrAssign", wk[0][1] if wk else None, "'UObject serial numbers overflowed' log, most callers")

        # AFortAthenaMapInfo::InitializeFlightPath(MapInfo, GameState, PhaseLogic, bool, float, float, float): fills
        # MapInfo->FlightInfos, which the map ships empty. The wrapper is the sole caller of the function logging
        # 'InitializeFlightPath: Can't properly align the bus...' (Remix 32.11 0x9101F80, same arguments).
        ifp = self.only_func(log_record_funcs(sc, "InitializeFlightPath: Can't properly align the bus"), "InitializeFlightPath inner")
        ifw = {img.func_start(c) for c in sc.callers(ifp)} if ifp else set()
        self.rva("InitializeFlightPath", self.only_func(ifw, "InitializeFlightPath"), "sole caller of the 'InitializeFlightPath: Can't properly align the bus' log function")
        # UFortControllerComponent_Aircraft::EnterAircraft(Component, Aircraft) / ExitAircraft(Component). Server-side
        # PlacePlayerInAircraft is stripped, these two are intact.
        self.rva("EnterAircraft", self.only_func(log_record_funcs(sc, "EnterAircraft: [%s] is attempting to enter aircraft"), "EnterAircraft"), "'EnterAircraft: [%s] is attempting to enter aircraft' log")
        self.rva("ExitAircraft", self.only_func(log_record_funcs(sc, "ExitAircraft: %s (Pawn"), "ExitAircraft"), "'ExitAircraft: %s (Pawn %s)' log")

        # GNatives: the bytecode dispatch table every exec thunk uses to step its parameters
        # (`lea r9,[rip+GNatives]` ... `call [r9+rax*8]`). Needed to read params in our own exec functions.
        gn = None
        th = self.exec_thunk("ServerCreateBuildingActor")
        if th:
            s_, e_ = img.func_bounds(th)
            ins = disasm(img, s_, n=e_ - s_)
            for i, x in enumerate(ins[:-6]):
                if x.mnemonic == "lea" and "rip" in x.op_str and any(y.mnemonic == "call" and "*8]" in y.op_str for y in ins[i + 1:i + 10]):
                    gn = rip_target(img, x)
                    break
        self.globals["GNatives"] = (gn, "`lea r9,[rip+X]` before `call [r9+rax*8]` in an exec thunk")

        # FThreadHeartBeat::CheckCheckpointHeartBeat: the host never reaches the game-flow checkpoints, so after 600s the
        # heartbeat thread crashes on purpose (write to 0x3). Hooked to return -1 like Remix (32.11 0x521AFC0).
        self.rva("CheckCheckpointHeartBeat", self.only_func(log_record_funcs(sc, "Failed to reach checkpoint within alotted time"), "CheckCheckpointHeartBeat"), "'Failed to reach checkpoint within alotted time' log (hooked, returns -1)")

        # ABuildingSMActor::ReplaceBuildingActor(Building, 1, UClass**, Level, RotationIterations, bMirrored, PC): edits.
        self.rva("ReplaceBuildingActor", self.only_func(sc.funcs_referencing("STAT_Fort_BuildingSMActorReplaceBuildingActor"), "ReplaceBuildingActor"), "L\"STAT_Fort_BuildingSMActorReplaceBuildingActor\"")

        # ABuildingContainer::SpawnLoot (virtual): only logs 'SpawnLoot() >>> START' in the client build. Hooked.
        self.rva("SpawnLoot", self.only_func(log_record_funcs(sc, "ABuildingContainer::SpawnLoot() >>> START"), "SpawnLoot"), "'ABuildingContainer::SpawnLoot() >>> START' log (hooked, loot spawned by us)")
        # AFortPickup::SetPickupTarget(Pickup, Pawn, FlyTime, const FVector& Direction, bPlaySound): flies the pickup to
        # the pawn. The pawn's ServerHandlePickupInfo that calls it is a ret stub.
        spt = self.rva("SetPickupTarget", self.only_func(sc.funcs_referencing("AFortPickup::SetPickupTarget", wide=False), "SetPickupTarget"), "A\"AFortPickup::SetPickupTarget\"")
        # AFortPickup::SetPickupItems(Pickup, Entry*, TArray<Entry>*, SourceType, bool, SpawnSource): the function right
        # before SetPickupTarget, opening with the authority check `cmp byte [rcx+0x14C],3` (Remix 32.11 0x9CDB314).
        spi = None
        if spt:
            x = spt - 1
            while img.u8(x) == 0xCC:
                x -= 1
            f = img.func_start(x)
            if f and bytes.fromhex("80B94C01000003") in img.read(f, 0x30):
                spi = f
        self.rva("SetPickupItems", spi, "function right before SetPickupTarget with the `cmp byte [rcx+0x14C],3` authority check")

        # IsNoMCP: `static bool = FParse::Param(cmdline, L"nomcp")`, the L"nomcp" reader with the most callers.
        nm = sorted(((f, len(sc.callers(f))) for f in sc.funcs_referencing("nomcp")), key=lambda x: -x[1])
        self.rva("NoMCP", nm[0][0] if nm else None, "L\"nomcp\" reader with the most callers (hooked)")
        # McpProfile SendRequestNow(this, Request, ContextCredentials): logs 'ContextCredentials' and 'SendRequestNow Error'.
        # The server's player profile queries go out as DedicatedServer (0), which the client build refuses; Remix forces 3 (Public).
        self.rva("DispatchRequest", self.only_func(log_record_funcs(sc, "ContextCredentials"), "DispatchRequest"), "'ContextCredentials' log (hooked, context forced to 3)")

        # UObject::GetInterfaceAddress(this, InterfaceClass): `test dword [rdx+0xD4],0x4000` (CLASS_Interface), walks
        # Class->Interfaces (+0x1D8). UClass::ImplementsInterface has the same test; GetInterfaceAddress is the one calling it.
        ifc = {img.func_start(h) for h in img.find_all(bytes.fromhex("F782D400000000400000"), sec=".text")} - {None}
        gia = [f for f in ifc if any(t in ifc for _, t in sc.calls_in(*img.func_bounds(f)))]
        self.rva("GetInterfaceAddress", self.only_func(gia, "GetInterfaceAddress"), "CLASS_Interface test, calls ImplementsInterface")

        # CreateNetDriver_Local(Engine, WorldContext&, FName Definition, FName Name): sets NetDriverDefinition and runs PostCreation,
        # which is what puts the driver on Iris. A NewObject'd driver stays on the Generic model, which the client build can't send.
        # Two functions carry its failure log (CreateNamedNetDriver_Local inlines it); take the one the other calls.
        cnd_logs = set(log_record_funcs(sc, "CreateNamedNetDriver failed to create driver"))
        cnd = [f for f in cnd_logs if any(img.func_start(c) in cnd_logs for c in sc.callers(f))]
        cnd = self.rva("CreateNetDriver", cnd[0] if len(cnd) == 1 else None, "'CreateNamedNetDriver failed to create driver' log, the one CreateNamedNetDriver calls")
        # UEngine::GetWorldContextFromWorld: the call right before CreateNetDriver_Local in its other caller (GEngine, GetWorld()).
        gwc = set()
        for c in (sc.callers(cnd) if cnd else []):
            f = img.func_start(c)
            if f in cnd_logs:
                continue
            prev = [x for x in disasm(img, f, c - f) if x.mnemonic == "call" and x.op_str.startswith("0x")]
            if prev:
                gwc.add(int(prev[-1].op_str, 16) - img.image_base)
        self.rva("GetWorldContextFromWorld", self.only_func(gwc, "GetWorldContextFromWorld"), "call before CreateNetDriver in its non-engine caller")

        # UNetDriver::GetNetMode: `mov rax,[rcx]; call [rax+0x3E8] (IsServer); test al; jne; mov eax,3`.
        drv = img.find_all(bytes.fromhex("4883EC28488B01FF90E803000084C00F85"), sec=".text")
        drv = self.rva("NetDriverGetNetMode", drv[0] if len(drv) == 1 else None, "IsServer vcall then `mov eax,3` byte pattern")
        # UWorld::GetNetMode (outlined): `cmp [rcx+0x38],0 ... mov eax,3`, sits right before UNetDriver::GetNetMode.
        wgm = [h for h in img.find_all(bytes.fromhex("4883EC284883793800488BD175"), sec=".text") if img.func_bounds(h) and img.func_bounds(h)[1] <= drv <= img.func_bounds(h)[1] + 16]
        self.rva("WorldGetNetMode", wgm[0] if len(wgm) == 1 else None, "`cmp [rcx+0x38],0` function directly before NetDriverGetNetMode")
        # Inlined copies of UWorld::GetNetMode: rewrite their NetDriver null-check branch (see netmode.py).
        self.patches, unhandled = netmode.find_sites(img, sc, adfu, drv)
        print("  netmode: %d inlined sites patched, %d left alone" % (len(self.patches), len(unhandled)))

        # AFortGameSession::KickPlayer (logs 'KickPlayer %s Reason %s'): kicks the host for having no reservation.
        kp = sorted(((f, len(sc.callers(f))) for f in log_record_funcs(sc, "KickPlayer %s Reason")), key=lambda x: -x[1])
        self.rva("KickPlayer", kp[0][0] if kp else None, "'KickPlayer %s Reason' log, most callers")
        # The virtual override logs the same string; the "No reservation in game" validation kick goes through it.
        kpv = [f for f, _ in kp if sc.ptrs_to(f)]
        self.rva("KickPlayerVirtual", kpv[0] if len(kpv) == 1 else None, "'KickPlayer %s Reason' log, the one in a vtable")

        # Lobby team-member widget refresh: derefs a null UI object once the world thinks it's a server (Remix "widget crash").
        self.rva("TeamMemberWidget", self.only_func(sc.funcs_referencing("TeamMemberEntry", exact=True), "TeamMemberWidget"), "L\"TeamMemberEntry\" (patched to ret)")
        # The same entry's virtual refresh: calls TeamMemberWidget first, then with a null argument dereferences the member
        # at +0x1490 that the (ret-patched) setup never created. Map-load crash; hooked to skip that case.
        tmw = self.rvas["TeamMemberWidget"][0]
        tmr = [img.func_start(c) for c in (sc.callers(tmw) if tmw else [])]
        tmr = [f for f in tmr if f and bytes.fromhex("488B8F90140000") in img.read(f, 0x60)]
        self.rva("TeamMemberRefresh", self.only_func(tmr, "TeamMemberRefresh"), "caller of TeamMemberWidget reading [rcx+0x1490] (hooked, null case skipped)")
        # UBattlePassScreenS31::ForEachSubPage: the frontend battle pass screen is still around on the host and walks its
        # sub-page container (+0xB18), null here, on map load. Hooked to skip a null container.
        self.rva("BattlePassForEachSubPage", self.only_func(sc.funcs_referencing("UBattlePassScreenS31::ForEachSubPage", wide=False, exact=True), "BattlePassForEachSubPage"), "A\"UBattlePassScreenS31::ForEachSubPage\" (hooked, null container skipped)")

        # UFortRootViewportLayout::NativeOnInitialized: binds delegates on BindWidget subobjects that never get built
        # in a server world (ConfirmationWindow at +0x3D8 is null) (Remix "controller disconnected").
        rvi = self.rva("RootViewportInit", self.only_func(sc.funcs_referencing("ControllerDisconnectedTitle", exact=True), "RootViewportInit"), "L\"ControllerDisconnectedTitle\" (patched to ret)")

        # UFortRootViewportLayout controller-disconnected modal toggle: `mov rcx,[rcx+0x3E8]` (ProgressModal_ControllerDisconnected,
        # null in a server world) then a vcall (Remix "nother controller").
        cd = img.find_all(bytes.fromhex("534883EC20488BD9B201488B89E8030000488B01"), sec=".text")
        self.rva("ControllerModal", cd[0] - 1 if len(cd) == 1 else None, "`mov rcx,[rcx+0x3E8]; mov dl,1` byte pattern (patched to ret)")

        # UFortRootViewportLayout::NativeConstruct: walks state/modal widgets that are all null on a server. Found via the
        # Athena NativeOnInitialized override (sole caller of RootViewportInit) -> its tail jmp -> the biggest caller of that.
        rvc = None
        ov = [img.func_start(c) for c in sc.callers(rvi)] if rvi else []
        if len(ov) == 1:
            s_, e_ = img.func_bounds(ov[0])
            last = disasm(img, s_, n=e_ - s_)[-1]
            if last.mnemonic == "jmp":
                tail = int(last.op_str, 16) - img.image_base
                cands = {img.func_start(c) for c in sc.callers(tail)}
                cands = {c for c in cands if sc.ptrs_to(c)}
                if cands:
                    rvc = max(cands, key=lambda f: len(sc.calls_in(*img.func_bounds(f))))
        self.rva("RootViewportConstruct", rvc, "largest vtable function calling the Athena NativeOnInitialized tail (patched to ret)")

        # ULocalPlayer::SpawnPlayActor: the caller of UWorld::SpawnPlayActor ('Login failed: %s' log) that sits in the
        # ULocalPlayer vtable. Returning true without spawning keeps the host from getting an Athena PC and HUD, whose
        # BindWidget members are null on a server (HitTicks HitMarker etc.) (Remix "localplayer spawnplayactor").
        wsp = self.only_func(log_record_funcs(sc, "Login failed: %s"), "UWorld::SpawnPlayActor")
        lpv = self.cls("ULocalPlayer").vtable
        spa = {img.func_start(c) for c in sc.callers(wsp)} if wsp else set()
        spa = [f for f in spa if lpv and sc.vtable_index(lpv, f) is not None]
        self.rva("SpawnPlayActor", spa[0] if len(spa) == 1 else None, "ULocalPlayer vtable caller of UWorld::SpawnPlayActor (patched to return true)")

        # UGameViewportSubsystem::AddToScreen(Widget, Player, Slot): every AddToViewport/AddToPlayerScreen/AddWidget goes
        # through it. The host's HUD still gets built on join without a PC (Quickbar Minimize on null QuickbarSlots), so
        # nothing is allowed on screen. Returns bool, callers handle false.
        ats = set(sc.funcs_referencing("The widget '%s' already has a parent widget. It can't also be added to the viewport!")) & set(sc.funcs_referencing("The widget '%s' was already added to the screen."))
        self.rva("AddToScreen", self.only_func(ats, "AddToScreen"), "L\"...already has a parent widget...\" + L\"...was already added to the screen.\" (patched to return false)")

        # Dynamic UI widget creation (ticker-driven, never goes through AddToScreen): the STAT_CreateWidget function that
        # calls the "SDynamicUIChild" builder. It built the Athena HUD on join (Quickbar Minimize on null QuickbarSlots).
        dch = self.only_func(sc.funcs_referencing("SDynamicUIChild", wide=False), "SDynamicUIChild builder")
        dcw = ({img.func_start(c) for c in sc.callers(dch)} & set(sc.funcs_referencing("STAT_CreateWidget"))) if dch else set()
        self.rva("DynamicUICreate", self.only_func(dcw, "DynamicUICreate"), "STAT_CreateWidget caller of the \"SDynamicUIChild\" builder (patched to ret)")

        # FortPlayerEligibilityResolver resolve: the VerifyAuth handler calls it on UFortGameInstance+0xD30 without a null
        # check, and the host never gets a resolver. Hooked to skip a null resolver.
        self.rva("ResolvePlayerEligibility", self.only_func(log_record_funcs(sc, "Resolving player eligibility for player ["), "ResolvePlayerEligibility"), "'Resolving player eligibility for player [' log (hooked, null this skipped)")

        # class vtables (documentation / sanity, hooks use the CDO vtable at runtime)
        for n in ("AFortGameModeAthena", "AFortPlayerControllerAthena", "UNetDriver", "UIpNetDriver"):
            ci = self.cls(n)
            self.rva("VTable_" + n, ci.vtable, "ctor lea (class registration chain)")

    # ---- output ----
    def write(self, path):
        lines = ["#pragma once", "#include <cstdint>", "",
                 "// 31.41 (5.5.0-37324991). Generated by tools/find_offsets.py from the flat client dump; do not edit by hand.",
                 "// Sig = first bytes of the function (rel32 wildcarded), checked at runtime by Finder::Verify.", "",
                 "namespace Offsets", "{"]
        lines.append("\t// natives (RVA)")
        for name, (v, how) in self.rvas.items():
            if name.startswith("VTable_"):
                continue
            lines.append("\tconstexpr uintptr_t %s = 0x%X; // %s" % (name, v or 0, how))
        lines.append("")
        lines.append("\t// signatures for the natives above")
        for name, (v, how) in self.rvas.items():
            if name.startswith("VTable_") or not v:
                continue
            lines.append("\tconstexpr const char* %s_Sig = \"%s\";" % (name, self.signature(v)))
        lines.append("")
        lines.append("\t// globals / member offsets")
        for name, (v, how) in self.globals.items():
            lines.append("\tconstexpr uintptr_t %s = 0x%X; // %s" % (name, v or 0, how))
        lines.append("")
        lines.append("\t// Inlined UWorld::GetNetMode sites: branch rewritten so NetDriver != null takes the null path (tools/netmode.py).")
        lines.append("\tstruct BytePatch { uintptr_t Rva; uint8_t Len; uint8_t Old[6]; uint8_t New[6]; };")
        lines.append("\tconstexpr BytePatch NetModePatches[] = {")
        fmt_b = lambda b: "{" + ", ".join("0x%02X" % c for c in b.ljust(6, b"\0")) + "}"
        for rva, old_b, new_b, note in self.patches:
            lines.append("\t\t{0x%X, %d, %s, %s}, // %s" % (rva, len(old_b), fmt_b(old_b), fmt_b(new_b), note))
        lines.append("\t};")
        lines.append("")
        lines.append("\t// vtable indices (hooked on the CDO vtable, so no absolute address needed)")
        lines.append("\tnamespace VT")
        lines.append("\t{")
        for name, (v, how) in self.idx.items():
            lines.append("\t\tconstexpr int %s = %d; // %s" % (name, v if v is not None else -1, how))
        lines.append("\t}")
        lines.append("")
        lines.append("\t// class vtables in the dump (reference only)")
        for name, (v, how) in self.rvas.items():
            if name.startswith("VTable_"):
                lines.append("\tconstexpr uintptr_t %s = 0x%X;" % (name, v or 0))
        lines.append("}")
        with open(path, "w", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    def report(self):
        print("== natives")
        for name, (v, how) in self.rvas.items():
            print("  %-36s %s  (%s)" % (name, ("0x%X" % v) if v else "MISSING", how))
        print("== globals")
        for name, (v, how) in self.globals.items():
            print("  %-36s %s  (%s)" % (name, ("0x%X" % v) if v else "MISSING", how))
        print("== vtable indices")
        for name, (v, how) in self.idx.items():
            print("  %-36s %s  (%s)" % (name, v if v is not None else "MISSING", how))
        if self.errors:
            print("!! missing:", self.errors)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    img = Image(a.dump) if a.dump else Image()
    print("dump:", img.path, "base 0x%X" % img.image_base)
    f = Finder(img)
    f.run()
    f.report()
    if not a.check:
        f.write(OUT)
        print("wrote", os.path.normpath(OUT))


if __name__ == "__main__":
    main()
