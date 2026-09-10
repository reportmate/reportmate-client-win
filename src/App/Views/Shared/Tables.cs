using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Markup;
using System.Windows.Media;

namespace ReportMate.App.Views.Shared;

/// <summary>Tone to pill background/foreground brushes, for pill cells bound to a Tone property.</summary>
public sealed class ToneBrushConverter : IValueConverter
{
    public bool Foreground { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var tone = value is Tone t ? t : Tone.Neutral;
        var key = tone switch
        {
            Tone.Success => "PillGreen",
            Tone.Warning => "PillYellow",
            Tone.Error => "PillRed",
            Tone.Info => "PillBlue",
            Tone.Purple => "PillPurple",
            Tone.Orange => "PillOrange",
            _ => "PillGray",
        };
        return Ui.Brush(key + (Foreground ? "Foreground" : "Background"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Usage percentage to a bar colour: green under 75, yellow under 90, red above.</summary>
public sealed class PercentBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var pct = value is double d ? d : value is int i ? i : 0;
        return pct > 90 ? Ui.StatusBrush(Tone.Error) : pct > 75 ? Ui.StatusBrush(Tone.Warning) : Ui.StatusBrush(Tone.Success);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>A column definition for <see cref="Table"/>.</summary>
public sealed class Col
{
    public string Header { get; init; } = "";
    public string Path { get; init; } = "";
    public string? SubPath { get; init; }
    public string? TonePath { get; init; }
    public ColKind Kind { get; init; } = ColKind.Text;
    public double? Width { get; init; }
    public double? MinWidth { get; init; }
    public bool Star { get; init; }
    public bool Mono { get; init; }
    public bool Wrap { get; init; }
    public bool Secondary { get; init; }

    public static Col Text(string header, string path, double? width = null, bool star = false, bool mono = false, string? sub = null, bool wrap = false, bool secondary = false)
        => new() { Header = header, Path = path, Width = width, Star = star, Mono = mono, SubPath = sub, Wrap = wrap, Secondary = secondary };

    public static Col Pill(string header, string path, string tonePath, double? width = null)
        => new() { Header = header, Path = path, TonePath = tonePath, Kind = ColKind.Pill, Width = width };

    /// <summary>Text with a thin usage bar under it; Path is the text, SubPath the 0-100 percent.</summary>
    public static Col Bar(string header, string path, string percentPath, double? width = null)
        => new() { Header = header, Path = path, SubPath = percentPath, Kind = ColKind.Bar, Width = width };

    /// <summary>A clickable link; Path is the text, SubPath the URL.</summary>
    public static Col Link(string header, string path, string urlPath, double? width = null)
        => new() { Header = header, Path = path, SubPath = urlPath, Kind = ColKind.Link, Width = width };
}

public enum ColKind { Text, Pill, Bar, Link }

/// <summary>Builds themed DataGrids from row objects and column definitions.</summary>
public static class Table
{
    private static readonly ToneBrushConverter ToneBg = new();
    private static readonly ToneBrushConverter ToneFg = new() { Foreground = true };
    private static readonly PercentBrushConverter PercentBrush = new();

    public static DataGrid Build(IEnumerable rows, params Col[] columns)
    {
        var grid = new DataGrid { Style = (Style)Ui.Res("GridStyle"), ItemsSource = rows };
        foreach (var col in columns) grid.Columns.Add(Column(col));
        return grid;
    }

    /// <summary>Grid inside a card, with an empty-state line when there are no rows.</summary>
    public static UIElement Card(string title, string? subtitle, IList rows, UIElement? headerRight = null, string empty = "Nothing to show", params Col[] columns)
    {
        UIElement body = rows.Count == 0 ? Ui.EmptyState(empty) : Build(rows, columns);
        return Ui.TableCard(title, subtitle, body, headerRight);
    }

    private static DataGridColumn Column(Col col)
    {
        var width = col.Star ? new DataGridLength(1, DataGridLengthUnitType.Star)
            : col.Width is { } w ? new DataGridLength(w)
            : DataGridLength.Auto;

        DataGridTemplateColumn column = new()
        {
            Header = col.Header,
            Width = width,
            MinWidth = col.MinWidth ?? 0,
            SortMemberPath = col.Path,
            CanUserSort = true,
        };

        column.CellTemplate = col.Kind switch
        {
            ColKind.Pill => PillTemplate(col),
            ColKind.Bar => BarTemplate(col),
            ColKind.Link => LinkTemplate(col),
            _ => TextTemplate(col),
        };
        return column;
    }

    private static DataTemplate TextTemplate(Col col)
    {
        var text = new FrameworkElementFactory(typeof(TextBlock));
        text.SetBinding(TextBlock.TextProperty, new Binding(col.Path));
        text.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
        text.SetValue(TextBlock.FontSizeProperty, 12.5);
        text.SetValue(TextBlock.ForegroundProperty, Ui.Brush(col.Secondary ? "TextSecondaryBrush" : "TextPrimaryBrush"));
        text.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
        text.SetValue(TextBlock.TextWrappingProperty, col.Wrap ? TextWrapping.Wrap : TextWrapping.NoWrap);
        text.SetBinding(FrameworkElement.ToolTipProperty, new Binding(col.Path));
        if (col.Mono) text.SetValue(TextBlock.FontFamilyProperty, (FontFamily)Ui.Res("MonoFont"));

        if (col.SubPath is null)
            return new DataTemplate { VisualTree = text };

        var panel = new FrameworkElementFactory(typeof(StackPanel));
        panel.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        panel.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 4, 0, 4));
        panel.AppendChild(text);
        var sub = new FrameworkElementFactory(typeof(TextBlock));
        sub.SetBinding(TextBlock.TextProperty, new Binding(col.SubPath));
        sub.SetValue(TextBlock.FontSizeProperty, 11.0);
        sub.SetValue(TextBlock.ForegroundProperty, Ui.Brush("TextSecondaryBrush"));
        sub.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
        sub.SetBinding(FrameworkElement.ToolTipProperty, new Binding(col.SubPath));
        sub.SetBinding(UIElement.VisibilityProperty, new Binding(col.SubPath) { Converter = (IValueConverter)Ui.Res("StringToVisibility") });
        panel.AppendChild(sub);
        return new DataTemplate { VisualTree = panel };
    }

    private static DataTemplate PillTemplate(Col col)
    {
        var border = new FrameworkElementFactory(typeof(Border));
        border.SetValue(Border.CornerRadiusProperty, new CornerRadius(999));
        border.SetValue(Border.PaddingProperty, new Thickness(9, 2, 9, 2));
        border.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Left);
        border.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        border.SetBinding(Border.BackgroundProperty, new Binding(col.TonePath!) { Converter = ToneBg });
        border.SetBinding(UIElement.VisibilityProperty, new Binding(col.Path) { Converter = (IValueConverter)Ui.Res("StringToVisibility") });
        var text = new FrameworkElementFactory(typeof(TextBlock));
        text.SetBinding(TextBlock.TextProperty, new Binding(col.Path));
        text.SetValue(TextBlock.FontSizeProperty, 11.5);
        text.SetValue(TextBlock.FontWeightProperty, FontWeights.Medium);
        text.SetBinding(TextBlock.ForegroundProperty, new Binding(col.TonePath!) { Converter = ToneFg });
        border.AppendChild(text);
        return new DataTemplate { VisualTree = border };
    }

    private static DataTemplate BarTemplate(Col col)
    {
        var panel = new FrameworkElementFactory(typeof(StackPanel));
        panel.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        var text = new FrameworkElementFactory(typeof(TextBlock));
        text.SetBinding(TextBlock.TextProperty, new Binding(col.Path));
        text.SetValue(TextBlock.FontSizeProperty, 12.5);
        text.SetValue(TextBlock.ForegroundProperty, Ui.Brush("TextPrimaryBrush"));
        panel.AppendChild(text);
        var track = new FrameworkElementFactory(typeof(Border));
        track.SetValue(FrameworkElement.HeightProperty, 5.0);
        track.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
        track.SetValue(Border.BackgroundProperty, Ui.Brush("SubtleFillBrush"));
        track.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 4, 0, 0));
        track.SetValue(FrameworkElement.MinWidthProperty, 80.0);
        var fill = new FrameworkElementFactory(typeof(Border));
        fill.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
        fill.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Left);
        fill.SetBinding(Border.BackgroundProperty, new Binding(col.SubPath!) { Converter = PercentBrush });
        fill.SetBinding(FrameworkElement.WidthProperty, new MultiBinding
        {
            Converter = new PercentWidthConverter(),
            Bindings = { new Binding(col.SubPath!), new Binding("ActualWidth") { RelativeSource = new RelativeSource(RelativeSourceMode.FindAncestor, typeof(Border), 1) } },
        });
        track.AppendChild(fill);
        panel.AppendChild(track);
        return new DataTemplate { VisualTree = panel };
    }

    private static DataTemplate LinkTemplate(Col col)
    {
        var text = new FrameworkElementFactory(typeof(TextBlock));
        text.SetBinding(TextBlock.TextProperty, new Binding(col.Path));
        text.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
        text.SetValue(TextBlock.FontSizeProperty, 12.5);
        text.SetValue(TextBlock.ForegroundProperty, Ui.StatusBrush(Tone.Info));
        text.SetValue(TextBlock.TextDecorationsProperty, TextDecorations.Underline);
        text.SetValue(FrameworkElement.CursorProperty, System.Windows.Input.Cursors.Hand);
        text.SetBinding(FrameworkElement.TagProperty, new Binding(col.SubPath!));
        text.AddHandler(UIElement.MouseLeftButtonUpEvent, new System.Windows.Input.MouseButtonEventHandler((s, _) =>
        {
            if (s is TextBlock tb && tb.Tag is string url && !string.IsNullOrWhiteSpace(url))
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = url, UseShellExecute = true }); } catch { }
        }));
        return new DataTemplate { VisualTree = text };
    }

    private sealed class PercentWidthConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
        {
            var pct = values.Length > 0 && values[0] is double d ? d : values.Length > 0 && values[0] is int i ? i : 0;
            var total = values.Length > 1 && values[1] is double w ? w : 0;
            return Math.Max(0, Math.Min(100, pct)) / 100.0 * total;
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    }
}

/// <summary>One choice in a <see cref="FilterPills"/> group.</summary>
public record FilterOption(string Key, string Label, int Count);

/// <summary>
/// The web FilterPills: segmented buttons showing each option's count, one active.
/// Rebuilds itself when the counts change so the distribution stays visible.
/// </summary>
public sealed class FilterPills : ContentControl
{
    private string _value;
    public event Action<string>? Changed;

    public FilterPills(IEnumerable<FilterOption> options, string value)
    {
        _value = value;
        Options = options.ToList();
        Render();
    }

    public List<FilterOption> Options { get; }
    public string Value => _value;

    private void Render()
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        var frame = new Border
        {
            CornerRadius = new CornerRadius(7),
            BorderBrush = Ui.Brush("CardBorderBrush"),
            BorderThickness = new Thickness(1),
            Child = panel,
            ClipToBounds = true,
            VerticalAlignment = VerticalAlignment.Center,
        };
        foreach (var option in Options)
        {
            var active = option.Key == _value;
            var text = new StackPanel { Orientation = Orientation.Horizontal };
            text.Children.Add(new TextBlock { Text = option.Label, FontSize = 11.5, FontWeight = FontWeights.Medium, VerticalAlignment = VerticalAlignment.Center });
            text.Children.Add(new TextBlock { Text = option.Count.ToString(), FontSize = 11, Opacity = 0.7, Margin = new Thickness(5, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center });
            var btn = new Border
            {
                Padding = new Thickness(10, 4, 10, 4),
                Background = active ? Ui.Brush("TextPrimaryBrush") : Ui.Brush("CardBackgroundBrush"),
                BorderBrush = Ui.Brush("CardBorderBrush"),
                BorderThickness = new Thickness(0, 0, 1, 0),
                Cursor = System.Windows.Input.Cursors.Hand,
                Child = text,
            };
            text.SetValue(TextElement.ForegroundProperty, active ? Ui.Brush("CardBackgroundBrush") : Ui.Brush("TextPrimaryBrush"));
            var key = option.Key;
            btn.MouseLeftButtonUp += (_, _) => { _value = key; Render(); Changed?.Invoke(key); };
            panel.Children.Add(btn);
        }
        if (panel.Children.Count > 0 && panel.Children[^1] is Border last) last.BorderThickness = new Thickness(0);
        Content = frame;
    }
}

/// <summary>Search box styled for table headers.</summary>
public sealed class SearchBox : TextBox
{
    public SearchBox(string placeholder, Action<string> onChanged)
    {
        Style = (Style)Ui.Res("FilterTextBoxStyle");
        ModernWpf.Controls.Primitives.ControlHelper.SetPlaceholderText(this, placeholder);
        TextChanged += (_, _) => onChanged(Text);
        Margin = new Thickness(8, 0, 0, 0);
    }
}

/// <summary>
/// A card holding a searchable, filterable table: title and "x of y" subtitle,
/// filter pill groups and a search box in the header, a DataGrid below.
/// </summary>
public sealed class FilteredTable<T> : ContentControl
{
    private readonly string _title;
    private readonly string _subtitleFormat;
    private readonly IReadOnlyList<T> _all;
    private readonly Func<T, string, bool> _search;
    private readonly Col[] _columns;
    private readonly List<(FilterPills Pills, Func<T, string, bool> Predicate)> _filters = [];
    private readonly Dictionary<FilterPills, string> _values = new();
    private string _query = "";
    private readonly TextBlock _subtitle = Ui.Text("", "SubtitleTextStyle");
    private readonly ContentControl _body = new() { HorizontalContentAlignment = HorizontalAlignment.Stretch };
    private readonly StackPanel _controls = new() { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
    private readonly string _searchPlaceholder;
    private readonly string _emptyMessage;
    private readonly Func<IEnumerable<T>, IEnumerable<T>>? _order;

    /// <param name="subtitleFormat">Use {0} for shown count and {1} for total.</param>
    public FilteredTable(string title, string subtitleFormat, IReadOnlyList<T> rows, Func<T, string, bool> search, Col[] columns,
        string searchPlaceholder = "Search...", string emptyMessage = "No rows match the current filters", Func<IEnumerable<T>, IEnumerable<T>>? order = null)
    {
        _title = title;
        _subtitleFormat = subtitleFormat;
        _all = rows;
        _search = search;
        _columns = columns;
        _searchPlaceholder = searchPlaceholder;
        _emptyMessage = emptyMessage;
        _order = order;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
    }

    /// <summary>
    /// Open with a search already applied, so a link can reopen the exact view it was
    /// copied from rather than the unfiltered table.
    /// </summary>
    public FilteredTable<T> WithQuery(string? query)
    {
        if (!string.IsNullOrWhiteSpace(query)) _query = query;
        return this;
    }

    /// <summary>Add a pill group. The predicate receives the row and the selected key ("all" passes everything).</summary>
    public FilteredTable<T> Filter(IEnumerable<FilterOption> options, Func<T, string, bool> predicate, string initial = "all")
    {
        var pills = new FilterPills(options, initial);
        _values[pills] = initial;
        pills.Changed += key => { _values[pills] = key; Refresh(); };
        pills.Margin = new Thickness(8, 0, 0, 0);
        _filters.Add((pills, predicate));
        return this;
    }

    public FilteredTable<T> Build()
    {
        foreach (var (pills, _) in _filters) _controls.Children.Add(pills);
        var search = new SearchBox(_searchPlaceholder, q => { _query = q; Refresh(); });
        if (!string.IsNullOrEmpty(_query)) search.Text = _query;
        _controls.Children.Add(search);
        var header = new StackPanel();
        header.Children.Add(Ui.Text(_title, "TitleTextStyle"));
        header.Children.Add(_subtitle);
        var card = Ui.TableCard("", null, _body, _controls);
        // Replace the empty title block with our own header (title + live subtitle).
        if (card.Child is StackPanel root && root.Children[0] is Grid headerGrid && headerGrid.Children[0] is StackPanel titles)
        {
            titles.Children.Clear();
            titles.Children.Add(header);
        }
        Content = card;
        Refresh();
        return this;
    }

    private void Refresh()
    {
        IEnumerable<T> rows = _all;
        foreach (var (pills, predicate) in _filters)
        {
            var key = _values[pills];
            if (key != "all") rows = rows.Where(r => predicate(r, key));
        }
        var q = _query.Trim();
        if (q.Length > 0) rows = rows.Where(r => _search(r, q));
        if (_order is not null) rows = _order(rows);
        var list = rows.ToList();
        _subtitle.Text = string.Format(_subtitleFormat, list.Count, _all.Count);
        _body.Content = list.Count == 0 ? Ui.EmptyState(_emptyMessage) : Table.Build(list, _columns);
    }
}
