using ObjCRuntime;
namespace ApproovSDK
{
    [Native]
    public enum ApproovTokenFetchStatus : ulong
    {
        Success,
        NoNetwork,
        MITMDetected,
        PoorNetwork,
        NoApproovService,
        BadURL,
        UnknownURL,
        UnprotectedURL,
        NotInitialized,
        Rejected,
        Disabled,
        UnknownKey,
        BadKey,
        BadPayload,
        InternalError
    }
}



