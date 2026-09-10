using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>Chart marks shared by the dashboard widgets and the fleet reports.</summary>
public static class Charts
{
    /// <summary>A labelled proportion bar. Bars, not pie slices: comparing lengths on a
    /// shared baseline is easier than comparing angles, and it scales past a few slices.</summary>
    public static UIElement Bar(string label, int count, int total, Tone tone)
    {
        var fraction = total <= 0 ? 0 : (double)count / total;

        var head = new Grid();
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var name = Ui.Text(label);
        name.FontSize = 12.5;
        name.TextTrimming = TextTrimming.CharacterEllipsis;
        head.Children.Add(name);
        var value = Ui.Caption($"{count:N0}  ·  {fraction:P0}");
        Grid.SetColumn(value, 1);
        head.Children.Add(value);

        var track = new Border
        {
            Height = 6,
            CornerRadius = new CornerRadius(3),
            Background = Ui.Brush("SubtleFillBrush"),
            Margin = new Thickness(0, 5, 0, 0),
        };
        var fill = new Border
        {
            Height = 6,
            CornerRadius = new CornerRadius(3),
            Background = Ui.StatusBrush(tone),
            HorizontalAlignment = HorizontalAlignment.Left,
        };
        track.Child = fill;
        track.SizeChanged += (_, e) => fill.Width = Math.Max(0, e.NewSize.Width * fraction);

        var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
        panel.Children.Add(head);
        panel.Children.Add(track);
        return panel;
    }

}
