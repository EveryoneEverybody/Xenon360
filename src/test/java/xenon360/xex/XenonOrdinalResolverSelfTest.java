package xenon360.xex;

public final class XenonOrdinalResolverSelfTest {
    private static int checks;

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void expect(String module, int ordinal, String name, boolean function) {
        XenonOrdinalResolver.Export export = XenonOrdinalResolver.resolve(module, ordinal);
        check(export != null, module + " ordinal 0x" + Integer.toHexString(ordinal) + " unresolved");
        check(export.name().equals(name),
            module + " ordinal 0x" + Integer.toHexString(ordinal) + " name=" + export.name());
        check(export.function() == function,
            module + " ordinal 0x" + Integer.toHexString(ordinal) + " kind mismatch");
    }

    public static void main(String[] args) {
        check(XenonOrdinalResolver.SOURCE_COMMIT.equals(
            "95a5c3ee250f80c3b9d139658649d9ffb6db3eec"), "source commit");
        check(XenonOrdinalResolver.knownCount("xam.xex") == 1735, "xam count");
        check(XenonOrdinalResolver.knownCount("XBOXKRNL.EXE") == 922, "xboxkrnl count");
        check(XenonOrdinalResolver.knownCount("xbdm.xex") == 255, "xbdm count");
        check(XenonOrdinalResolver.knownCount("drivers.xex") == 115, "unambiguous drivers count");
        check(XenonOrdinalResolver.knownCount("xnet.xex") == 133, "xnet count");
        check(XenonOrdinalResolver.knownCount("xnetd.dll") == 133, "xnetd alias count");
        check(XenonOrdinalResolver.knownCount("XAPI.XEX") == 5, "xapi count");
        check(XenonOrdinalResolver.knownCount("connectx.dll") == 24, "connectx count");
        check(XenonOrdinalResolver.knownCount("unknown.xex") == 0, "unknown module count");

        expect("xam.xex", 0x0191, "XamInputGetState", true);
        expect("xam.xex", 0x0219, "XamUserReadProfileSettings", true);
        expect("xam.xex", 0x021a, "XamUserWriteProfileSettings", true);
        expect("xam.xex", 0x0227, "XamUserGetSigninInfo", true);
        expect("xboxkrnl.exe", 0x00d2, "NtCreateFile", true);
        expect("xboxkrnl.exe", 0x0125, "RtlEnterCriticalSection", true);
        expect("xboxkrnl.exe", 0x018f, "XeCryptShaInit", true);
        expect("xboxkrnl.exe", 0x0195, "XexGetModuleHandle", true);
        expect("xboxkrnl.exe", 0x0156, "XboxHardwareInfo", false);
        expect("xbdm.xex", 0x0001, "DmAllocatePool", true);
        expect("xbdm.xex", 0x0028, "DmSetMemory", true);
        expect("xbdm.xex", 0x0091, "DmFindPdbSignature", true);
        expect("xbdm.xex", 0x0174, "DmExecuteThreadRPC", true);
        expect("drivers.xex", 0x0001, "VdBlockUntilGUIIdle", true);
        expect("drivers.xex", 0x0003, "VdEdramHeap", false);
        expect("drivers.xex", 0x0007, "VdGetCurrentAVPack", true);
        expect("drivers.xex", 0x0077, "VdDisplayFatalError", true);
        expect("xnet.xex", 0x004b, "NetDll_XNetGetEthernetLinkStatus", true);
        expect("xnetd.dll", 0x0134, "XNetLogonSetConsoleCertificate", true);
        expect("XAPI.XEX", 0x0001, "XapiProcessHeap", false);
        expect("XAPI.XEX", 0x0002, "_locktable", false);
        expect("XAPI.XEX", 0x0003, "__tlsindexXapi", false);
        expect("XAPI.XEX", 0x0004, "XapiTermHeapNoop", true);
        expect("XAPI.XEX", 0x0005, "XapiDebugHeap", false);
        expect("connectx.dll", 0x0001, "CxGetVersion", true);
        expect("connectx.dll", 0x0018, "SmbWriteFile", true);

        // Neither observed DLL generation may win when the importer cannot select it.
        for (String module : new String[] { "drivers.xex", "DRIVERS.DLL", "drivers", "lib/drivers.xex" }) {
            for (int ordinal : new int[] { 0x0004, 0x0016, 0x002c, 0x002d }) {
                check(XenonOrdinalResolver.resolve(module, ordinal) == null,
                    module + " generation-conflicting ordinal " + ordinal + " must stay unresolved");
            }
        }
        check(XenonOrdinalResolver.resolve("xam.xex", 0x7fffffff) == null,
            "unknown ordinal must remain unresolved");
        check(XenonOrdinalResolver.resolve(null, 1) == null, "null module");

        System.out.println("XENON_ORDINAL_SELF_TEST_PASS checks=" + checks
            + " xam=1735 xboxkrnl=922 xbdm=255 drivers=115 withheld=4 xnet=133 xapi=5 connectx=24");
    }
}
