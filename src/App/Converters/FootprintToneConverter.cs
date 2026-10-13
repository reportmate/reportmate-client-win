using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using ReportMate.Shared;

namespace ReportMate.App.Converters;

/// <summary>The theme brush for a Services row's state dot.</summary>
public sealed class FootprintToneConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var key = value switch
        {
            FootprintTone.Success => "SystemFillColorSuccessBrush",
            FootprintTone.Attention => "SystemFillColorAttentionBrush",
            _ => "SystemFillColorNeutralBrush",
        };
        return Application.Current.Resources[key];
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotSupportedException();
}
