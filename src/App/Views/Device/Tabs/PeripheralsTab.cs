using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using InputDevice = ReportMate.WindowsClient.Models.Modules.InputDevice;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>
/// Peripherals by category with a filter strip: external storage, USB and
/// Thunderbolt, audio, input devices, printers, scanners, microphones, Bluetooth,
/// plus cameras and serial ports the client reports on Windows.
/// </summary>
public sealed class PeripheralsTab : DeviceTab
{
    public override string Id => "peripherals";
    public override string Label => "Peripherals";
    public override string Glyph => "";
    public override Accent Accent => Accent.Cyan;
    public override string Description => "Displays, printers, and connected peripherals";

    private string? _filter;

    private sealed record Category(string Id, string Name, string Glyph, int Count, Accent Accent);

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("peripherals") || s.Peripherals is null) return ModuleMissing("peripherals", s);
        var p = s.Peripherals;
        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader("Peripherals", "Connected devices by category", Glyph, Accent));

        var usb = p.UsbDevicesFlat;
        var thunderbolt = p.ThunderboltDevicesFlat;
        var audio = p.AudioDevicesFlat;
        var outputs = audio.Where(a => a.IsOutput || string.Equals(a.Type, "Output", StringComparison.OrdinalIgnoreCase)).ToList();
        var mics = audio.Where(a => a.IsInput || string.Equals(a.Type, "Input", StringComparison.OrdinalIgnoreCase)).ToList();
        var input = p.InputDevicesFlat;
        var keyboards = ByType(input, "keyboard");
        var mice = ByType(input, "mouse");
        var trackpads = ByType(input, "trackpad", "touchpad");
        var tablets = ByType(input, "graphics tablet", "tablet", "pen display", "pen tablet", "pen input");
        var others = input.Where(d => !keyboards.Contains(d) && !mice.Contains(d) && !trackpads.Contains(d) && !tablets.Contains(d)).ToList();
        var bluetooth = p.BluetoothDevicesFlat.Where(IsPeripheral).ToList();
        var btKeyboards = bluetooth.Where(b => string.Equals(b.DeviceType, "Keyboard", StringComparison.OrdinalIgnoreCase) || string.Equals(b.DeviceCategory, "Keyboard", StringComparison.OrdinalIgnoreCase)).ToList();
        var printers = p.PrintersFlat;
        var scanners = p.ScannersFlat;
        var storage = p.StorageDevicesFlat;
        var cameras = p.CamerasFlat;
        var serial = p.SerialPortsFlat;

        var categories = new List<Category>
        {
            new("storage", "External Storage", "", storage.Count, Accent.Red),
            new("usb", "USB & Thunderbolt", "", usb.Count + thunderbolt.Count, Accent.Blue),
            new("audio", "Audio", "", outputs.Count, Accent.Green),
            new("input", "Input Devices", "", keyboards.Count + mice.Count + trackpads.Count + tablets.Count + others.Count + btKeyboards.Count, Accent.Purple),
            new("printers", "Printers", "", printers.Count, Accent.Orange),
            new("scanners", "Scanners", "", scanners.Count, Accent.Indigo),
            new("microphones", "Microphones", "", mics.Count, Accent.Pink),
            new("bluetooth", "Bluetooth", "", bluetooth.Count, Accent.Cyan),
        };
        if (cameras.Count > 0) categories.Add(new("cameras", "Cameras", "", cameras.Count, Accent.Teal));
        if (serial.Count > 0) categories.Add(new("serial", "Serial Ports", "", serial.Count, Accent.Gray));

        if (categories.All(c => c.Count == 0))
        {
            page.Children.Add(Ui.Card(Ui.EmptyState("No peripheral devices were reported. Connect a device and run a collection to see it here.", "")));
            return page;
        }

        var host = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
        void Render()
        {
            var root = new StackPanel();
            var strip = new WrapPanel();
            foreach (var c in categories)
            {
                var active = _filter == c.Id;
                var content = new StackPanel { Orientation = Orientation.Horizontal };
                content.Children.Add(Ui.Icon(c.Glyph, 13, active ? Ui.Brush("CardBackgroundBrush") : Ui.Brush($"Icon{c.Accent}Foreground")));
                content.Children.Add(new TextBlock { Text = c.Name, FontSize = 12.5, FontWeight = FontWeights.Medium, Margin = new Thickness(7, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center, Foreground = active ? Ui.Brush("CardBackgroundBrush") : Ui.Brush("TextPrimaryBrush") });
                var count = Ui.Pill(c.Count.ToString(), Tone.Neutral, 10.5);
                content.Children.Add(count);
                var btn = new Border
                {
                    Padding = new Thickness(10, 6, 8, 6), CornerRadius = new CornerRadius(8), Margin = new Thickness(0, 0, 8, 8), Cursor = Cursors.Hand,
                    Background = active ? Ui.Brush("IconBlueForeground") : Ui.Brush("CardBackgroundBrush"),
                    BorderBrush = Ui.Brush("CardBorderBrush"), BorderThickness = new Thickness(1), Child = content, Opacity = c.Count == 0 ? 0.55 : 1,
                };
                var id = c.Id;
                btn.MouseLeftButtonUp += (_, _) => { _filter = _filter == id ? null : id; Render(); };
                strip.Children.Add(btn);
            }
            root.Children.Add(Ui.Card(strip, new Thickness(16, 16, 8, 8)));

            bool Visible(string id) => _filter is null || _filter == id;
            void Section(string id, string glyph, string title, IEnumerable<UIElement> cards, string? subtitle = null)
            {
                var list = cards.ToList();
                if (!Visible(id) || list.Count == 0) return;
                var section = new StackPanel { Margin = new Thickness(0, 24, 0, 0) };
                section.Children.Add(Ui.SectionTitle(glyph, title));
                if (subtitle is not null) { var sub = Ui.Caption(subtitle); sub.Margin = new Thickness(0, -6, 0, 10); section.Children.Add(sub); }
                var grid = Ui.CardGrid(300, 16);
                grid.MaxColumns = 4;
                foreach (var card in list) grid.Children.Add(card);
                section.Children.Add(grid);
                root.Children.Add(section);
            }

            Section("storage", "", "External Storage", storage.Select(d => DeviceCard(DeviceSnapshot.FirstNonEmpty(d.Name, d.VolumeName) ?? "External Storage", "", d.StorageType ?? d.DriveType,
                ("File System", d.FileSystem?.ToUpperInvariant()), ("Volume", d.VolumeName), ("Device", d.DevicePath), ("Size", d.TotalSize), ("Free", d.FreeSpace), ("Serial", d.SerialNumber), ("Connection", d.ConnectionType))));

            if (Visible("printers") && printers.Count > 0)
            {
                var section = new StackPanel { Margin = new Thickness(0, 24, 0, 0) };
                section.Children.Add(Ui.SectionTitle("", "Printers"));
                foreach (var pr in printers.OrderByDescending(x => x.IsDefault ? 1 : 0).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                {
                    var card = PrinterCard(pr);
                    card.Margin = new Thickness(0, 0, 0, 12);
                    section.Children.Add(card);
                }
                root.Children.Add(section);
            }

            Section("audio", "", "Audio Output", outputs.Select(a => DeviceCard(a.Name ?? "Audio Output", "", a.IsDefault ? "Default" : null,
                ("Manufacturer", a.Manufacturer), ("Connection", a.ConnectionType), ("Type", a.IsBuiltIn ? "Built-in" : "External"), ("Status", a.Status))));
            Section("scanners", "", "Scanners", scanners.Select(sc => DeviceCard(sc.Name ?? "Scanner", "", sc.ScannerType,
                ("Manufacturer", sc.Manufacturer), ("Connection", sc.ConnectionType), ("Status", sc.Status))));
            Section("microphones", "", "Microphones", mics.Select(a => DeviceCard(a.Name ?? "Microphone", "", a.IsDefault ? "Default" : null,
                ("Manufacturer", a.Manufacturer), ("Connection", a.ConnectionType), ("Type", a.IsBuiltIn ? "Built-in" : "External"), ("Status", a.Status))));

            if (Visible("usb") && (usb.Count > 0 || thunderbolt.Count > 0))
            {
                var section = new StackPanel { Margin = new Thickness(0, 24, 0, 0) };
                section.Children.Add(Ui.SectionTitle("", "USB & Thunderbolt"));
                if (thunderbolt.Count > 0)
                {
                    section.Children.Add(Ui.Eyebrow("Thunderbolt"));
                    var g = Ui.CardGrid(300, 16); g.MaxColumns = 4; g.Margin = new Thickness(0, 6, 0, 14);
                    foreach (var t in thunderbolt) g.Children.Add(DeviceCard(t.Name ?? "Thunderbolt Device", "", t.DeviceType, ("Vendor", t.Vendor), ("Device ID", t.DeviceId), ("UID", t.Uid), ("Connection", t.ConnectionType)));
                    section.Children.Add(g);
                }
                if (usb.Count > 0)
                {
                    section.Children.Add(Ui.Eyebrow("USB Devices"));
                    var g = Ui.CardGrid(300, 16); g.MaxColumns = 4; g.Margin = new Thickness(0, 6, 0, 0);
                    foreach (var u in usb.Where(u => !u.IsCompositeChild).Concat(usb.Where(u => u.IsCompositeChild)))
                        g.Children.Add(DeviceCard(DeviceSnapshot.FirstNonEmpty(u.Name, u.Model) ?? "Unknown USB Device", "", u.IsCompositeChild ? "Composite" : (u.Removable ? "Removable" : u.Class),
                            ("Vendor", u.Vendor), ("Vendor ID", u.VendorId), ("Product ID", u.ModelId), ("Serial", u.SerialNumber), ("Class", u.Class), ("Instance", u.DeviceInstanceId)));
                    section.Children.Add(g);
                }
                root.Children.Add(section);
            }

            if (Visible("bluetooth") && bluetooth.Count > 0)
            {
                var section = new StackPanel { Margin = new Thickness(0, 24, 0, 0) };
                section.Children.Add(Ui.SectionTitle("", "Bluetooth Peripherals"));
                var connected = bluetooth.Where(b => b.IsConnected).ToList();
                var paired = bluetooth.Where(b => !b.IsConnected).ToList();
                if (connected.Count > 0)
                {
                    section.Children.Add(Ui.Eyebrow("Connected"));
                    var g = Ui.CardGrid(300, 16); g.MaxColumns = 4; g.Margin = new Thickness(0, 6, 0, 14);
                    foreach (var b in connected) g.Children.Add(DeviceCard(b.Name ?? "Bluetooth Device", "", "Connected", Tone.Success, ("Category", b.DeviceCategory), ("Type", b.DeviceType), ("Address", b.Address), ("Manufacturer", b.Manufacturer), ("Last Seen", b.LastSeen)));
                    section.Children.Add(g);
                }
                if (paired.Count > 0)
                {
                    section.Children.Add(Ui.Eyebrow("Paired"));
                    var g = Ui.CardGrid(300, 16); g.MaxColumns = 4; g.Margin = new Thickness(0, 6, 0, 0);
                    foreach (var b in paired) g.Children.Add(DeviceCard(b.Name ?? "Bluetooth Device", "", "Paired", Tone.Neutral, ("Category", b.DeviceCategory), ("Type", b.DeviceType), ("Address", b.Address), ("Last Seen", b.LastSeen)));
                    section.Children.Add(g);
                }
                root.Children.Add(section);
            }

            if (Visible("input") && (keyboards.Count + mice.Count + trackpads.Count + tablets.Count + others.Count + btKeyboards.Count) > 0)
            {
                var section = new StackPanel { Margin = new Thickness(0, 24, 0, 0) };
                section.Children.Add(Ui.SectionTitle("", "Input Devices"));
                void Group(string title, IEnumerable<UIElement> cards)
                {
                    var list = cards.ToList();
                    if (list.Count == 0) return;
                    section.Children.Add(Ui.Eyebrow(title));
                    var g = Ui.CardGrid(300, 16); g.MaxColumns = 4; g.Margin = new Thickness(0, 6, 0, 14);
                    foreach (var c in list) g.Children.Add(c);
                    section.Children.Add(g);
                }
                Group("Keyboards", keyboards.Select(InputCard).Concat(btKeyboards.Select(b => DeviceCard(b.Name ?? "Keyboard", "", "Bluetooth", ("Address", b.Address)))));
                Group("Mice", mice.Select(InputCard));
                Group("Trackpads", trackpads.Select(InputCard));
                Group("Pen Input", tablets.Select(t => DeviceCard(t.Name ?? "Graphics Tablet", "", DeviceSnapshot.FirstNonEmpty(t.TabletType) ?? "Pen Input",
                    ("Vendor", t.Vendor), ("Vendor ID", t.VendorId), ("Product ID", t.ProductId), ("Serial", t.SerialNumber), ("Connection", t.ConnectionType))));
                Group("Other", others.Select(InputCard));
                root.Children.Add(section);
            }

            Section("cameras", "", "Cameras", cameras.Select(c => DeviceCard(c.Name ?? "Camera", "", c.IsBuiltIn ? "Built-in" : c.ConnectionType,
                ("Manufacturer", c.Manufacturer), ("Model ID", c.ModelId), ("Connection", c.ConnectionType), ("Status", c.Status))));
            Section("serial", "", "Serial Ports", serial.Select(sp => DeviceCard(sp.Name ?? "Serial Port", "", sp.PortType,
                ("Device", sp.Device), ("Connection", sp.ConnectionType))));

            if (root.Children.Count == 1)
                root.Children.Add(SetTop(Ui.Card(Ui.EmptyState("No devices in this category."))));
            host.Content = root;
        }
        Render();
        page.Children.Add(host);
        return page;
    }

    private static FrameworkElement SetTop(FrameworkElement e) { e.Margin = new Thickness(0, 24, 0, 0); return e; }

    private static List<InputDevice> ByType(List<InputDevice> devices, params string[] types)
        => devices.Where(d => types.Contains((d.DeviceType ?? "").ToLowerInvariant())).ToList();

    private static UIElement InputCard(InputDevice d) => DeviceCard(d.Name ?? Format.OrUnknown(d.DeviceType), "", d.ConnectionType,
        ("Vendor", d.Vendor), ("Vendor ID", d.VendorId), ("Product ID", d.ProductId), ("Serial", d.SerialNumber), ("Type", d.IsBuiltIn ? "Built-in" : "External"), ("Description", d.Description != d.Name ? d.Description : null));

    /// <summary>Exclude phones, computers, watches and the HomePod family the way the web tab does.</summary>
    private static bool IsPeripheral(BluetoothDevice d)
    {
        var name = (d.Name ?? "").ToLowerInvariant();
        var category = (d.DeviceCategory ?? "").ToLowerInvariant();
        if (name.Contains("homepod") || name.Contains("apple watch") || name.Contains("iphone") || name.Contains("ipad") || name.Contains("macbook") || name.Contains("imac") || name.Contains("mac mini") || name.Contains("mac pro") || name.Contains("mac studio")) return false;
        return category is not ("computer" or "phone" or "tablet" or "watch");
    }

    private static Border DeviceCard(string title, string glyph, string? badge, params (string Label, string? Value)[] rows)
        => DeviceCard(title, glyph, badge, Tone.Neutral, rows);

    private static Border DeviceCard(string title, string glyph, string? badge, Tone badgeTone, params (string Label, string? Value)[] rows)
    {
        var head = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var titleRow = new StackPanel { Orientation = Orientation.Horizontal };
        titleRow.Children.Add(Ui.Icon(glyph, 14, Ui.Brush("TextSecondaryBrush")));
        var t = Ui.Text(title); t.FontWeight = FontWeights.SemiBold; t.Margin = new Thickness(8, 0, 0, 0); t.TextTrimming = TextTrimming.CharacterEllipsis; t.TextWrapping = TextWrapping.NoWrap; t.ToolTip = title;
        titleRow.Children.Add(t);
        head.Children.Add(titleRow);
        if (!string.IsNullOrWhiteSpace(badge))
        {
            var b = Ui.Pill(badge, badgeTone, 10.5);
            Grid.SetColumn(b, 1);
            head.Children.Add(b);
        }
        var body = new StackPanel();
        body.Children.Add(head);
        foreach (var (label, value) in rows)
        {
            if (string.IsNullOrWhiteSpace(value)) continue;
            var r = Ui.Row(label, value, mono: label is "Vendor ID" or "Product ID" or "Serial" or "Address" or "Device" or "Instance" or "Device ID" or "UID", semibold: false);
            r.Margin = new Thickness(0, 2, 0, 2);
            body.Children.Add(r);
        }
        return Ui.Card(body, new Thickness(16, 12, 16, 12));
    }

    private static Border PrinterCard(PeripheralInstalledPrinter pr)
    {
        var body = new StackPanel();
        var head = new Grid { Margin = new Thickness(0, 0, 0, 10) };
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var titleRow = new StackPanel { Orientation = Orientation.Horizontal };
        titleRow.Children.Add(Ui.Icon("", 16, Ui.Brush("IconOrangeForeground")));
        var t = Ui.Text(DeviceSnapshot.FirstNonEmpty(pr.DisplayName, pr.Name) ?? "Printer"); t.FontWeight = FontWeights.SemiBold; t.FontSize = 15; t.Margin = new Thickness(8, 0, 0, 0);
        titleRow.Children.Add(t);
        head.Children.Add(titleRow);
        var badges = new StackPanel { Orientation = Orientation.Horizontal };
        if (pr.IsDefault) { var b = Ui.Pill("Default", Tone.Success); b.Margin = new Thickness(6, 0, 0, 0); badges.Children.Add(b); }
        if (pr.IsShared) { var b = Ui.Pill("Shared", Tone.Info); b.Margin = new Thickness(6, 0, 0, 0); badges.Children.Add(b); }
        if (pr.IsNetwork) { var b = Ui.Pill("Network", Tone.Neutral); b.Margin = new Thickness(6, 0, 0, 0); badges.Children.Add(b); }
        Grid.SetColumn(badges, 1);
        head.Children.Add(badges);
        body.Children.Add(head);

        if (!string.IsNullOrWhiteSpace(pr.PortName)) body.Children.Add(Ui.Stat("Queue / Port", pr.PortName, mono: true, copy: true));
        var left = new StackPanel();
        var right = new StackPanel();
        void Add(StackPanel col, string label, string? value) { if (!string.IsNullOrWhiteSpace(value)) col.Children.Add(Ui.Row(label, value, semibold: false)); }
        Add(left, "Manufacturer", pr.Manufacturer);
        Add(left, "Model", pr.Model);
        Add(left, "Driver", pr.Driver);
        Add(left, "Driver Version", pr.DriverVersion);
        Add(left, "Connection", pr.ConnectionType);
        Add(right, "Status", pr.Status);
        Add(right, "Location", pr.Location);
        Add(right, "Share Name", pr.ShareName);
        Add(right, "Server", pr.ServerName);
        Add(right, "Comment", pr.Comment);
        var grid = Ui.Columns(2, 24, left, right);
        grid.Margin = new Thickness(0, 10, 0, 0);
        body.Children.Add(grid);
        return Ui.Card(body, new Thickness(20, 14, 20, 16));
    }
}
