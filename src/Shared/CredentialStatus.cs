namespace ReportMate.Shared;

/// <summary>
/// What the app says about a stored credential. Only an elevated process can read the
/// protected store, so the normal app cannot know whether one is saved and does not guess;
/// a value entered there is saved through the UAC prompt on Save. The value itself is never shown.
/// </summary>
public static class CredentialStatus
{
    public const string NotReadable = "Enter a value to set or replace it";

    public static string Describe(bool isElevated, bool isSaved) =>
        !isElevated ? NotReadable
        : isSaved ? "Saved — enter a new value to replace it"
        : "Not saved";
}
