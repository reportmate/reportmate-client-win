using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using ModernWpf.Controls;
using ReportMate.App.Services;

namespace ReportMate.App.Views.Shared;

/// <summary>Widget accent colours; keys map onto the Icon*Background/Foreground theme brushes.</summary>
public enum Accent { Blue, Orange, Red, Green, Purple, Indigo, Yellow, Teal, Cyan, Emerald, Pink, Gray, Mono }

/// <summary>Pill / badge colouring, matching the web StatusBadge types.</summary>
public enum Tone { Neutral, Success, Warning, Error, Info, Purple, Orange }

/// <summary>
/// Code-first building blocks shared by every device tab: the StatBlock card, Stat
/// label/value pairs, StatusBadge rows, pills, sections and simple grids. The tab
/// bodies are data-driven and conditional, so composing them in code keeps each tab
/// a straight port of its web counterpart instead of a wall of converters.
/// </summary>
public static class Ui
{
    public static Brush Brush(string key) =>
        Application.Current.TryFindResource(key) as Brush ?? Brushes.Transparent;

    public static object Res(string key) => Application.Current.FindResource(key);

    // ── Text ─────────────────────────────────────────────────────────

    public static TextBlock Text(string? text, string style = "StatValueStyle", Brush? foreground = null)
    {
        var tb = new TextBlock { Text = text ?? "", Style = (Style)Res(style) };
        if (foreground is not null) tb.Foreground = foreground;
        return tb;
    }

    public static TextBlock Label(string text) => Text(text, "StatLabelStyle");
    public static TextBlock Caption(string? text) => Text(text, "CaptionTextStyle");
    public static TextBlock Mono(string? text) => Text(text, "MonoValueStyle");
    public static TextBlock SectionHeader(string text) => Text(text, "SectionHeaderStyle");
    public static TextBlock Eyebrow(string text) => Text(text, "EyebrowTextStyle");

    public static TextBlock Status(string? text, Tone tone, double size = 13, FontWeight? weight = null)
    {
        var tb = Text(text);
        tb.FontSize = size;
        tb.FontWeight = weight ?? FontWeights.Medium;
        tb.Foreground = StatusBrush(tone);
        return tb;
    }

    public static Brush StatusBrush(Tone tone) => tone switch
    {
        Tone.Success => Brush("StatusGreenBrush"),
        Tone.Warning => Brush("StatusYellowBrush"),
        Tone.Orange => Brush("StatusOrangeBrush"),
        Tone.Error => Brush("StatusRedBrush"),
        Tone.Info => Brush("StatusBlueBrush"),
        Tone.Purple => Brush("IconPurpleForeground"),
        _ => Brush("TextSecondaryBrush"),
    };

    public static FontIcon Icon(string glyph, double size = 14, Brush? foreground = null)
    {
        var icon = new FontIcon { Glyph = glyph, FontSize = size, VerticalAlignment = VerticalAlignment.Center };
        if (foreground is not null) icon.Foreground = foreground;
        return icon;
    }

    // ── Layout ───────────────────────────────────────────────────────

    public static StackPanel Stack(double spacing = 12, Orientation orientation = Orientation.Vertical, params UIElement[] children)
    {
        var panel = new StackPanel { Orientation = orientation };
        foreach (var child in children)
        {
            if (child is FrameworkElement fe && panel.Children.Count > 0)
                fe.Margin = orientation == Orientation.Vertical
                    ? new Thickness(fe.Margin.Left, spacing, fe.Margin.Right, fe.Margin.Bottom)
                    : new Thickness(spacing, fe.Margin.Top, fe.Margin.Right, fe.Margin.Bottom);
            panel.Children.Add(child);
        }
        return panel;
    }

    public static StackPanel VStack(params UIElement[] children) => Stack(12, Orientation.Vertical, children);
    public static StackPanel HStack(params UIElement[] children) => Stack(8, Orientation.Horizontal, children);

    /// <summary>Equal-width columns with a gap; each child fills one column in order.</summary>
    public static Grid Columns(int count, double gap, params UIElement?[] children)
        => Columns(Enumerable.Repeat(1.0, count).ToArray(), gap, children);

    /// <summary>Star-weighted columns with a gap.</summary>
    public static Grid Columns(double[] weights, double gap, params UIElement?[] children)
    {
        var grid = new Grid();
        for (var i = 0; i < weights.Length; i++)
        {
            if (i > 0) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(gap) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(weights[i], GridUnitType.Star) });
        }
        var col = 0;
        foreach (var child in children)
        {
            if (child is not null)
            {
                Grid.SetColumn(child, col * 2);
                grid.Children.Add(child);
            }
            col++;
        }
        return grid;
    }

    /// <summary>Responsive card grid: cards wrap into as many columns as fit at the given minimum width.</summary>
    public static UniformCardPanel CardGrid(double minWidth = 380, double gap = 24) => new() { MinItemWidth = minWidth, Gap = gap };

    public static WrapPanel Wrap(double gap = 8, params UIElement[] children)
    {
        var panel = new WrapPanel { Orientation = Orientation.Horizontal };
        foreach (var child in children)
        {
            if (child is FrameworkElement fe) fe.Margin = new Thickness(0, 0, gap, gap);
            panel.Children.Add(child);
        }
        return panel;
    }

    public static Border Divider() => new()
    {
        Height = 1,
        Background = Brush("DividerBrush"),
        Margin = new Thickness(0, 4, 0, 4),
    };

    public static Border Spacer(double height) => new() { Height = height };

    // ── Cards ────────────────────────────────────────────────────────

    /// <summary>The web StatBlock: icon tile, title, subtitle, optional header-right and a body.</summary>
    public static Border StatBlock(string title, string? subtitle, string glyph, Accent accent, UIElement body, UIElement? headerRight = null)
    {
        var card = new Border { Style = (Style)Res("CardStyle") };
        var root = new StackPanel();

        var header = new Grid { Margin = new Thickness(20, 14, 20, 14) };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var tile = new Border
        {
            Width = 40, Height = 40, CornerRadius = new CornerRadius(8),
            Background = Brush($"Icon{accent}Background"),
            Child = Icon(glyph, 18, Brush($"Icon{accent}Foreground")),
            Margin = new Thickness(0, 0, 12, 0),
            VerticalAlignment = VerticalAlignment.Center,
        };
        ((FontIcon)tile.Child).HorizontalAlignment = HorizontalAlignment.Center;
        header.Children.Add(tile);

        var titles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        titles.Children.Add(Text(title, "TitleTextStyle"));
        if (!string.IsNullOrEmpty(subtitle)) titles.Children.Add(Text(subtitle, "SubtitleTextStyle"));
        Grid.SetColumn(titles, 1);
        header.Children.Add(titles);

        if (headerRight is not null)
        {
            Grid.SetColumn(headerRight, 2);
            if (headerRight is FrameworkElement fe) fe.VerticalAlignment = VerticalAlignment.Center;
            header.Children.Add(headerRight);
        }

        root.Children.Add(header);
        root.Children.Add(new Border { Height = 1, Background = Brush("DividerBrush") });

        var content = new Border { Padding = new Thickness(20, 16, 20, 18), Child = body };
        root.Children.Add(content);
        card.Child = root;
        return card;
    }

    /// <summary>A plain card with padded content, for tables and sections.</summary>
    public static Border Card(UIElement body, Thickness? padding = null)
        => new() { Style = (Style)Res("CardStyle"), Child = body, Padding = padding ?? new Thickness(20, 16, 20, 16) };

    /// <summary>Card with a bordered title row and unpadded body (tables).</summary>
    public static Border TableCard(string title, string? subtitle, UIElement body, UIElement? headerRight = null)
    {
        var card = new Border { Style = (Style)Res("CardStyle") };
        var root = new StackPanel();
        var header = new Grid { Margin = new Thickness(20, 14, 20, 14) };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var titles = new StackPanel();
        titles.Children.Add(Text(title, "TitleTextStyle"));
        if (!string.IsNullOrEmpty(subtitle)) titles.Children.Add(Text(subtitle, "SubtitleTextStyle"));
        header.Children.Add(titles);
        if (headerRight is not null)
        {
            Grid.SetColumn(headerRight, 1);
            if (headerRight is FrameworkElement fe) fe.VerticalAlignment = VerticalAlignment.Center;
            header.Children.Add(headerRight);
        }
        root.Children.Add(header);
        root.Children.Add(new Border { Height = 1, Background = Brush("DividerBrush") });
        root.Children.Add(body);
        card.Child = root;
        return card;
    }

    // ── Stat rows ────────────────────────────────────────────────────

    /// <summary>Label over value, optionally monospaced with a copy button, and an optional sublabel.</summary>
    public static FrameworkElement Stat(string label, string? value, bool mono = false, bool copy = false, string? sublabel = null, bool truncate = false)
    {
        var panel = new StackPanel { MinWidth = 0 };
        panel.Children.Add(Label(label));
        var shown = string.IsNullOrWhiteSpace(value) ? "Unknown" : value;
        var valueText = mono ? Mono(shown) : Text(shown);
        if (truncate)
        {
            valueText.TextWrapping = TextWrapping.NoWrap;
            valueText.TextTrimming = TextTrimming.CharacterEllipsis;
            valueText.ToolTip = shown;
        }
        if (copy && !string.IsNullOrWhiteSpace(value))
        {
            var row = new DockPanel { LastChildFill = true };
            var btn = CopyButton(value);
            DockPanel.SetDock(btn, Dock.Right);
            row.Children.Add(btn);
            row.Children.Add(valueText);
            panel.Children.Add(row);
        }
        else
        {
            panel.Children.Add(valueText);
        }
        if (!string.IsNullOrEmpty(sublabel)) panel.Children.Add(Caption(sublabel));
        return panel;
    }

    /// <summary>Label on the left, value on the right (settings-style row).</summary>
    public static Grid Row(string label, UIElement value)
    {
        var grid = new Grid { Margin = new Thickness(0, 3, 0, 3) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var l = Text(label, "StatValueStyle", Brush("TextSecondaryBrush"));
        l.Margin = new Thickness(0);
        grid.Children.Add(l);
        Grid.SetColumn(value, 1);
        if (value is FrameworkElement fe) fe.HorizontalAlignment = HorizontalAlignment.Right;
        grid.Children.Add(value);
        return grid;
    }

    public static Grid Row(string label, string? value, bool mono = false, bool semibold = true)
    {
        var v = mono ? Mono(OrUnknown(value)) : Text(OrUnknown(value));
        v.Margin = new Thickness(0);
        v.TextAlignment = TextAlignment.Right;
        if (semibold) v.FontWeight = FontWeights.SemiBold;
        return Row(label, v);
    }

    /// <summary>Label with a coloured pill on the right; the web StatusBadge.</summary>
    public static Grid StatusBadge(string label, string? status, Tone tone)
        => Row(label, Pill(OrUnknown(status), tone));

    public static Border Pill(string? text, Tone tone = Tone.Neutral, double fontSize = 12)
    {
        var (bg, fg) = tone switch
        {
            Tone.Success => ("PillGreenBackground", "PillGreenForeground"),
            Tone.Warning => ("PillYellowBackground", "PillYellowForeground"),
            Tone.Error => ("PillRedBackground", "PillRedForeground"),
            Tone.Info => ("PillBlueBackground", "PillBlueForeground"),
            Tone.Purple => ("PillPurpleBackground", "PillPurpleForeground"),
            Tone.Orange => ("PillOrangeBackground", "PillOrangeForeground"),
            _ => ("PillGrayBackground", "PillGrayForeground"),
        };
        var tb = new TextBlock
        {
            Text = text ?? "", FontSize = fontSize, FontWeight = FontWeights.Medium,
            Foreground = Brush(fg), VerticalAlignment = VerticalAlignment.Center,
        };
        return new Border
        {
            Style = (Style)Res("PillStyle"),
            Background = Brush(bg),
            Child = tb,
        };
    }

    /// <summary>A pill that copies its text when clicked (header identifiers).</summary>
    public static Border CopyPill(string text, string tooltip, bool mono = true)
    {
        var pill = Pill(text);
        pill.Cursor = Cursors.Hand;
        pill.ToolTip = tooltip;
        if (mono) ((TextBlock)pill.Child).FontFamily = (FontFamily)Res("MonoFont");
        pill.MouseLeftButtonUp += (_, _) => ClipboardHelper.Copy(text);
        pill.MouseEnter += (_, _) => pill.Background = Brush("SubtleFillHoverBrush");
        pill.MouseLeave += (_, _) => pill.Background = Brush("PillGrayBackground");
        return pill;
    }

    public static Button CopyButton(string? value)
    {
        var btn = new Button
        {
            Style = (Style)Res("ChromeIconButtonStyle"),
            Padding = new Thickness(4),
            Margin = new Thickness(6, 0, 0, 0),
            ToolTip = "Copy to clipboard",
            Content = Icon("", 12, Brush("TextTertiaryBrush")),
            VerticalAlignment = VerticalAlignment.Center,
        };
        btn.Click += (_, _) =>
        {
            ClipboardHelper.Copy(value);
            btn.Content = Icon("", 12, Brush("StatusGreenBrush"));
            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (_, _) => { btn.Content = Icon("", 12, Brush("TextTertiaryBrush")); timer.Stop(); };
            timer.Start();
        };
        return btn;
    }

    public static FrameworkElement EmptyState(string message, string glyph = "")
    {
        var panel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 16, 0, 16) };
        panel.Children.Add(Icon(glyph, 28, Brush("TextTertiaryBrush")));
        var tb = Text(message, "SubtitleTextStyle");
        tb.TextAlignment = TextAlignment.Center;
        tb.Margin = new Thickness(0, 8, 0, 0);
        panel.Children.Add(tb);
        return panel;
    }

    /// <summary>A card whose entire body is an empty state.</summary>
    public static Border EmptyCard(string title, string message, string glyph = "")
    {
        var body = EmptyState(message, glyph);
        return Card(VStack(SectionHeader(title), body));
    }

    // ── List items ───────────────────────────────────────────────────

    /// <summary>Title/subtitle on the left, optional badge and value on the right, divider below.</summary>
    public static Border ListItem(string title, string? subtitle = null, string? badge = null, Tone badgeTone = Tone.Info, string? value = null, UIElement? right = null)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var left = new StackPanel();
        var t = Text(title);
        t.FontWeight = FontWeights.Medium;
        t.Margin = new Thickness(0);
        t.TextTrimming = TextTrimming.CharacterEllipsis;
        t.TextWrapping = TextWrapping.NoWrap;
        left.Children.Add(t);
        if (!string.IsNullOrEmpty(subtitle))
        {
            var s = Caption(subtitle);
            s.TextTrimming = TextTrimming.CharacterEllipsis;
            s.TextWrapping = TextWrapping.NoWrap;
            left.Children.Add(s);
        }
        grid.Children.Add(left);
        var rightPanel = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        if (!string.IsNullOrEmpty(badge)) rightPanel.Children.Add(Pill(badge, badgeTone));
        if (!string.IsNullOrEmpty(value))
        {
            var v = Text(value);
            v.FontWeight = FontWeights.Medium;
            v.Margin = new Thickness(8, 0, 0, 0);
            rightPanel.Children.Add(v);
        }
        if (right is not null) rightPanel.Children.Add(right);
        Grid.SetColumn(rightPanel, 1);
        grid.Children.Add(rightPanel);
        return new Border
        {
            Padding = new Thickness(0, 8, 0, 8),
            BorderBrush = Brush("DividerBrush"),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Child = grid,
        };
    }

    public static StackPanel List(IEnumerable<UIElement> items)
    {
        var panel = new StackPanel();
        foreach (var item in items) panel.Children.Add(item);
        if (panel.Children.Count > 0 && panel.Children[^1] is Border last)
            last.BorderThickness = new Thickness(0);
        return panel;
    }

    // ── Buttons ──────────────────────────────────────────────────────

    public static Button IconButton(string glyph, string label, RoutedEventHandler onClick, string? tooltip = null)
    {
        var content = new StackPanel { Orientation = Orientation.Horizontal };
        content.Children.Add(Icon(glyph, 13));
        var tb = new TextBlock { Text = label, Margin = new Thickness(6, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
        content.Children.Add(tb);
        var btn = new Button { Content = content, ToolTip = tooltip, Padding = new Thickness(10, 5, 10, 5) };
        btn.Click += onClick;
        return btn;
    }

    /// <summary>Segmented filter buttons; returns the panel and invokes onSelect with the chosen key.</summary>
    public static StackPanel Segmented(IEnumerable<(string Key, string Label)> options, string selected, Action<string> onSelect)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        var group = Guid.NewGuid().ToString();
        foreach (var (key, label) in options)
        {
            var rb = new RadioButton
            {
                Content = label, Tag = key, GroupName = group,
                Style = (Style)Res("NavigationTabStyle"),
                IsChecked = key == selected,
            };
            rb.Checked += (_, _) => onSelect(key);
            panel.Children.Add(rb);
        }
        var frame = new Border
        {
            CornerRadius = new CornerRadius(9),
            BorderBrush = Brush("CardBorderBrush"),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(2),
            Child = panel,
        };
        var host = new StackPanel { Orientation = Orientation.Horizontal };
        host.Children.Add(frame);
        return host;
    }

    public static string OrUnknown(string? value) => string.IsNullOrWhiteSpace(value) ? "Unknown" : value;

    public static Tone ToneFor(bool? enabled, string? status = null)
    {
        if (enabled == true || status is "Enabled" or "Current" or "Protected" or "Active" or "Enrolled" or "Compliant" or "Up to date")
            return Tone.Success;
        if (enabled == false || status is "Disabled" or "Not Protected" or "Inactive" or "Not Enrolled")
            return Tone.Error;
        return Tone.Warning;
    }
}

/// <summary>
/// Wrap panel that lays cards out in equal-width columns: as many as fit at
/// MinItemWidth, each stretched to share the row. Cards in a row stretch to the
/// tallest so the grid reads like the web's CSS grid rather than a ragged wrap.
/// </summary>
public sealed class UniformCardPanel : Panel
{
    public double MinItemWidth { get; set; } = 380;
    public double Gap { get; set; } = 24;
    public int MaxColumns { get; set; } = 3;

    private int ColumnsFor(double width)
    {
        var cols = (int)Math.Floor((width + Gap) / (MinItemWidth + Gap));
        return Math.Clamp(cols, 1, Math.Max(1, Math.Min(MaxColumns, InternalChildren.Count == 0 ? 1 : InternalChildren.Count)));
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var width = double.IsInfinity(availableSize.Width) ? MinItemWidth * MaxColumns : availableSize.Width;
        var cols = ColumnsFor(width);
        var itemWidth = (width - Gap * (cols - 1)) / cols;
        double height = 0, rowHeight = 0;
        var i = 0;
        foreach (UIElement child in InternalChildren)
        {
            child.Measure(new Size(itemWidth, double.PositiveInfinity));
            rowHeight = Math.Max(rowHeight, child.DesiredSize.Height);
            if (++i % cols == 0) { height += rowHeight + Gap; rowHeight = 0; }
        }
        if (i % cols != 0) height += rowHeight + Gap;
        return new Size(width, Math.Max(0, height - Gap));
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var cols = ColumnsFor(finalSize.Width);
        var itemWidth = (finalSize.Width - Gap * (cols - 1)) / cols;
        double y = 0;
        var children = InternalChildren.Cast<UIElement>().ToList();
        for (var start = 0; start < children.Count; start += cols)
        {
            var row = children.Skip(start).Take(cols).ToList();
            var rowHeight = row.Max(c => c.DesiredSize.Height);
            for (var c = 0; c < row.Count; c++)
                row[c].Arrange(new Rect(c * (itemWidth + Gap), y, itemWidth, rowHeight));
            y += rowHeight + Gap;
        }
        return finalSize;
    }
}
