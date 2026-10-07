namespace ReportMate.Shared;

/// <summary>
/// What the app says about a stored credential. Only an elevated (unlocked) process can
/// read the protected store, so an unelevated one cannot know and says so instead of
/// guessing. The value itself is never shown.
/// </summary>
public static class CredentialStatus
{
    public const string UnlockToView = "Unlock to view";

    public static string Describe(bool isElevated, bool isSaved) =>
        !isElevated ? UnlockToView
        : isSaved ? "Saved — enter a new value to replace it"
        : "Not saved";
}
