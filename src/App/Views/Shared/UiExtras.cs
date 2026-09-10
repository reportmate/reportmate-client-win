using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace ReportMate.App.Views.Shared;

public static partial class Ui
{
    /// <summary>Tab page header: icon tile, title, subtitle, optional element on the right.</summary>
    public static Grid TabHeader(string title, string subtitle, string glyph, Accent accent, UIElement? right = null)
    {
        var grid = new Grid { Margin = new Thickness(0, 0, 0, 20) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var tile = new Border
        {
            Width = 48, Height = 48, CornerRadius = new CornerRadius(10),
            Background = Brush($"Icon{accent}Background"),
            Child = Icon(glyph, 22, Brush($"Icon{accent}Foreground")),
            Margin = new Thickness(0, 0, 14, 0),
        };
        ((FrameworkElement)tile.Child).HorizontalAlignment = HorizontalAlignment.Center;
        grid.Children.Add(tile);
        var titles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        titles.Children.Add(Text(title, "PageTitleTextStyle"));
        titles.Children.Add(Text(subtitle, "SubtitleTextStyle"));
        Grid.SetColumn(titles, 1);
        grid.Children.Add(titles);
        if (right is not null)
        {
            Grid.SetColumn(right, 2);
            if (right is FrameworkElement fe) fe.VerticalAlignment = VerticalAlignment.Center;
            grid.Children.Add(right);
        }
        return grid;
    }

    /// <summary>Label over a large value in a bordered tile; the web's data-point cards.</summary>
    public static Border Tile(string label, string? value, UIElement? extra = null, bool mono = false)
    {
        var panel = new StackPanel();
        panel.Children.Add(Caption(label));
        var v = Text(OrUnknown(value));
        v.FontSize = 16;
        v.FontWeight = FontWeights.SemiBold;
        v.TextTrimming = TextTrimming.CharacterEllipsis;
        v.ToolTip = value;
        if (mono) v.FontFamily = (FontFamily)Res("MonoFont");
        panel.Children.Add(v);
        if (extra is not null)
        {
            if (extra is FrameworkElement fe) fe.Margin = new Thickness(0, 6, 0, 0);
            panel.Children.Add(extra);
        }
        return new Border
        {
            Style = (Style)Res("CardStyle"),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(14, 10, 14, 12),
            Child = panel,
        };
    }

    /// <summary>Big number over a caption, for the statistics strips.</summary>
    public static Border Metric(string value, string label, Tone tone = Tone.Neutral)
    {
        var panel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
        var v = new TextBlock { Text = value, FontSize = 26, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center,
            Foreground = tone == Tone.Neutral ? Brush("TextPrimaryBrush") : StatusBrush(tone) };
        panel.Children.Add(v);
        var l = Caption(label);
        l.HorizontalAlignment = HorizontalAlignment.Center;
        panel.Children.Add(l);
        return new Border { Style = (Style)Res("CardStyle"), Padding = new Thickness(12, 14, 12, 14), Child = panel };
    }

    /// <summary>Equal tiles across the row.</summary>
    public static Grid TileRow(double gap, params UIElement?[] tiles)
    {
        var present = tiles.Where(t => t is not null).ToArray();
        return Columns(present.Length, gap, present);
    }

    /// <summary>Section heading with a leading icon, used between cards on a tab.</summary>
    public static StackPanel SectionTitle(string glyph, string title)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 10) };
        panel.Children.Add(Icon(glyph, 16, Brush("TextSecondaryBrush")));
        var t = SectionHeader(title);
        t.Margin = new Thickness(8, 0, 0, 0);
        t.VerticalAlignment = VerticalAlignment.Center;
        panel.Children.Add(t);
        return panel;
    }

    /// <summary>Spec card: icon + heading, a headline value, then detail lines.</summary>
    public static Border SpecCard(string glyph, string title, string headline, params string?[] details)
    {
        var panel = new StackPanel();
        var head = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
        head.Children.Add(Icon(glyph, 14, Brush("TextSecondaryBrush")));
        var t = Label(title);
        t.Margin = new Thickness(6, 0, 0, 0);
        t.VerticalAlignment = VerticalAlignment.Center;
        head.Children.Add(t);
        panel.Children.Add(head);
        var v = Text(headline);
        v.FontSize = 18;
        v.FontWeight = FontWeights.SemiBold;
        v.TextTrimming = TextTrimming.CharacterEllipsis;
        v.ToolTip = headline;
        panel.Children.Add(v);
        foreach (var d in details.Where(d => !string.IsNullOrWhiteSpace(d)))
        {
            var c = Caption(d);
            c.TextTrimming = TextTrimming.CharacterEllipsis;
            c.TextWrapping = TextWrapping.NoWrap;
            c.ToolTip = d;
            panel.Children.Add(c);
        }
        return new Border { Style = (Style)Res("CardStyle"), CornerRadius = new CornerRadius(8), Padding = new Thickness(14, 12, 14, 12), Child = panel };
    }

    /// <summary>Thin horizontal usage bar coloured by percentage.</summary>
    public static Grid UsageBar(double percent, double height = 6)
    {
        var grid = new Grid { Height = height };
        grid.Children.Add(new Border { CornerRadius = new CornerRadius(height / 2), Background = Brush("SubtleFillBrush") });
        var clamped = Math.Clamp(percent, 0, 100);
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Math.Max(clamped, 0.001), GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Math.Max(100 - clamped, 0.001), GridUnitType.Star) });
        var fill = new Border
        {
            CornerRadius = new CornerRadius(height / 2),
            Background = clamped > 90 ? StatusBrush(Tone.Error) : clamped > 75 ? StatusBrush(Tone.Warning) : StatusBrush(Tone.Success),
        };
        Grid.SetColumn(fill, 0);
        grid.Children.Add(fill);
        return grid;
    }

    /// <summary>A donut chart of (value, colour) segments with a centre label; the storage overview.</summary>
    public static Grid Donut(IEnumerable<(double Value, Brush Brush, string Tip)> segments, double total, string centre, string centreLabel, double size = 160, double thickness = 24)
    {
        var grid = new Grid { Width = size, Height = size };
        var radius = size / 2;
        var r = radius - thickness / 2;
        grid.Children.Add(new Ellipse
        {
            Width = size - thickness, Height = size - thickness,
            Stroke = Brush("SubtleFillBrush"), StrokeThickness = thickness,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
        });
        double start = -90;
        foreach (var (value, brush, tip) in segments)
        {
            if (total <= 0 || value <= 0) continue;
            var sweep = Math.Min(360 - (start + 90), value / total * 360);
            if (sweep <= 0) break;
            var path = new System.Windows.Shapes.Path { Stroke = brush, StrokeThickness = thickness, ToolTip = tip, Data = Arc(radius, radius, r, start, sweep) };
            grid.Children.Add(path);
            start += sweep;
        }
        var label = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        label.Children.Add(new TextBlock { Text = centre, FontSize = 22, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center, Foreground = Brush("TextPrimaryBrush") });
        var cl = Caption(centreLabel);
        cl.HorizontalAlignment = HorizontalAlignment.Center;
        label.Children.Add(cl);
        grid.Children.Add(label);
        return grid;
    }

    private static Geometry Arc(double cx, double cy, double r, double startDeg, double sweepDeg)
    {
        var startRad = startDeg * Math.PI / 180;
        var endRad = (startDeg + sweepDeg) * Math.PI / 180;
        var p1 = new Point(cx + r * Math.Cos(startRad), cy + r * Math.Sin(startRad));
        var p2 = new Point(cx + r * Math.Cos(endRad), cy + r * Math.Sin(endRad));
        var figure = new PathFigure { StartPoint = p1, IsClosed = false, IsFilled = false };
        figure.Segments.Add(new ArcSegment(p2, new Size(r, r), 0, sweepDeg > 180, SweepDirection.Clockwise, true));
        var geo = new PathGeometry();
        geo.Figures.Add(figure);
        return geo;
    }

    /// <summary>Collapsible section with a chevron header.</summary>
    public static Expander Collapsible(string title, UIElement body, bool open = false)
        => new()
        {
            Header = Text(title, "StatLabelStyle"),
            Content = body,
            IsExpanded = open,
            Margin = new Thickness(0, 4, 0, 0),
            Foreground = Brush("TextPrimaryBrush"),
        };

    /// <summary>Colour for a storage directory category, matching the web palette.</summary>
    public static Brush CategoryBrush(string? category, string? name)
    {
        if (name == "ProgramData") return new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44));
        return category switch
        {
            "ProgramFiles" => new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)),
            "Users" => new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)),
            "System" => new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)),
            "Other" => new SolidColorBrush(Color.FromRgb(0x8B, 0x5C, 0xF6)),
            "ProgramData" => new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44)),
            _ => new SolidColorBrush(Color.FromRgb(0x6B, 0x72, 0x80)),
        };
    }
}
