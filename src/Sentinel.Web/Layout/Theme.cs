using MudBlazor;

namespace Sentinel.Web.Layout;

public static class Theme
{
    public static readonly MudTheme Dark = new()
    {
        PaletteDark = new PaletteDark
        {
            Primary = "#4f8cff",
            Secondary = "#22d3ee",
            Tertiary = "#a970ff",
            Error = "#ff4d6d",
            Warning = "#ff8a3d",
            Success = "#2ecc71",
            Info = "#39d0ff",
            Background = "#0a0f1d",
            Surface = "#111a2e",
            AppbarBackground = "#0d1426",
            DrawerBackground = "#0d1426",
            TextPrimary = "#e6ecff",
            TextSecondary = "#8b9bbf",
            LinesDefault = "rgba(255,255,255,0.08)",
            TableLines = "rgba(255,255,255,0.06)",
            Divider = "rgba(255,255,255,0.08)",
        },
    };
}
