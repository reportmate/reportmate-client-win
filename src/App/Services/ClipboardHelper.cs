using System.Windows;

namespace ReportMate.App.Services;

public static class ClipboardHelper
{
    /// <summary>Silent copy; clipboard access can fail when another process holds it.</summary>
    public static void Copy(string? text)
    {
        if (string.IsNullOrEmpty(text)) return;
        try { Clipboard.SetText(text); } catch { }
    }
}
