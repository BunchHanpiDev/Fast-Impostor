namespace Impostor.Api.Innersloth
{
    /// <summary>
    /// Result of a report attempt.
    /// </summary>
    public enum ReportOutcome : byte
    {
        NotReportedUnknown = 0,
        NotReportedNoAccount = 1,
        NotReportedNotFound = 2,
        NotReportedRateLimit = 3,
        Reported = 4,
    }
}
