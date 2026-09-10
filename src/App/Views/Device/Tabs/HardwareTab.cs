using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ReportMate.App.Services;
using ReportMate.App.Views.Device.Widgets;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>Hardware specs, displays, storage analysis, storage devices, battery and memory modules.</summary>
public sealed class HardwareTab : DeviceTab
{
    public override string Id => "hardware";
    public override string Label => "Hardware";
    public override string Glyph => "";
    public override Accent Accent => Accent.Orange;
    public override string Description => "Hardware specifications and performance";

    private sealed record DriveRow(string Name, string Model, string Serial, string Type, string Capacity, string Free, double UsedPercent, string FileSystem, string Health, Tone HealthTone, string Interface);
    private sealed record ModuleRow(string Location, string Type, string Capacity, string Speed, string Manufacturer);

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("hardware") || s.Hardware is null) return ModuleMissing("hardware");
        var hw = s.Hardware;
        var page = new StackPanel();
        void Add(UIElement e, double top = 24) { if (e is FrameworkElement fe && page.Children.Count > 0) fe.Margin = new Thickness(0, top, 0, 0); page.Children.Add(e); }

        var arch = DeviceSnapshot.FirstNonEmpty(hw.Processor?.Architecture, s.System?.OperatingSystem?.Architecture);
        UIElement? right = null;
        if (!string.IsNullOrWhiteSpace(arch))
        {
            var p = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
            p.Children.Add(Ui.Caption("Architecture"));
            p.Children.Add(Ui.Pill(arch, Tone.Neutral));
            right = p;
        }
        Add(Ui.TabHeader("Hardware Overview", "System hardware specifications and components", Glyph, Accent, right), 0);

        // Identity + spec grid in one card
        var identity = Ui.Columns(3, 16,
            Ui.Stat("Manufacturer", Format.OrUnknown(hw.Manufacturer)),
            Ui.Stat("Model", Format.OrUnknown(hw.Model)),
            null);
        var identityBox = new Border
        {
            BorderBrush = Ui.Brush("CardBorderBrush"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8),
            Padding = new Thickness(16, 12, 16, 14), Child = identity, Margin = new Thickness(0, 0, 0, 16),
        };

        var cpu = hw.Processor;
        var cores = cpu?.Cores > 0 ? cpu.Cores : cpu?.LogicalProcessors ?? 0;
        var memory = hw.Memory;
        var module = memory?.Modules?.FirstOrDefault();
        var memoryDetail = string.Join(" ", new[] { module?.Type, module?.Manufacturer }.Where(v => !string.IsNullOrWhiteSpace(v) && v != "Unknown"));
        var (total, free) = HardwareWidget.InternalStorage(hw.Storage);
        var firstInternal = hw.Storage?.FirstOrDefault(d => d.IsInternal && d.Capacity > 0);
        var gpu = hw.Graphics;
        var gpuVram = gpu?.MemorySize > 0 ? $"{Math.Round(gpu.MemorySize / 1024.0 / 1024 / 1024, 1)} GB VRAM" : null;
        var gpuDetail = !string.IsNullOrWhiteSpace(gpu?.Manufacturer)
            ? $"{gpu.Manufacturer}{(string.IsNullOrWhiteSpace(gpu.DriverVersion) ? "" : $" - Driver {gpu.DriverVersion}")}"
            : "Graphics adapter";
        var battery = hw.Battery;
        var hasBattery = battery is not null && (battery.CycleCount > 0 || battery.ChargePercent > 0);
        var npu = hw.Npu;
        var hasNpu = npu is { IsAvailable: true } && !string.IsNullOrWhiteSpace(npu.Name);
        var wireless = hw.Wireless;
        var bluetooth = hw.Bluetooth;

        var row1 = Ui.Columns(4, 12,
            Ui.SpecCard("", "CPU", cores > 0 ? $"{cores} Cores" : "Unknown", Format.OrUnknown(cpu?.Name),
                cpu?.MaxSpeed > 0 ? $"Max: {cpu.MaxSpeed} GHz" : null),
            Ui.SpecCard("", "Memory", memory?.TotalPhysical > 0 ? Format.Bytes(memory.TotalPhysical) : "Unknown", memoryDetail,
                memory?.Modules is { Count: > 0 } ? $"{memory.Modules.Count} Modules" : null),
            Ui.SpecCard("", "Storage", total > 0 ? Format.Bytes(total) : "Unknown", total > 0 ? $"{Format.Bytes(free)} Free" : null,
                firstInternal?.Type is { Length: > 0 } t ? t : "Internal"),
            hasBattery
                ? Ui.SpecCard("", "Battery", $"{battery!.CycleCount} Cycles", $"{battery.ChargePercent}% • {Format.OrUnknown(battery.Health)}")
                : new Border());
        var row2 = Ui.Columns(4, 12,
            Ui.SpecCard("", "GPU", Format.OrUnknown(gpu?.Name), gpuVram, gpuDetail),
            hasNpu ? Ui.SpecCard("", "NPU", npu!.ComputeUnits > 0 ? $"{npu.ComputeUnits} TOPS" : Format.OrUnknown(npu.Name), npu.Name, npu.Architecture) : new Border(),
            wireless is { IsAvailable: true }
                ? Ui.SpecCard("", "Wireless", Format.OrUnknown(DeviceSnapshot.FirstNonEmpty(wireless.WifiGeneration, "Available")), wireless.Protocol, wireless.Name)
                : new Border(),
            bluetooth is { IsAvailable: true }
                ? Ui.SpecCard("", "Bluetooth", Format.OrNa(bluetooth.BluetoothVersion), Format.OrUnknown(bluetooth.Status) == "Unknown" ? "Available" : bluetooth.Status)
                : new Border());
        row2.Margin = new Thickness(0, 12, 0, 0);
        Add(Ui.Card(Ui.VStack(identityBox, row1, row2), new Thickness(16)));

        // Displays
        var displays = hw.Displays ?? [];
        if (displays.Count > 0)
        {
            var list = new StackPanel();
            foreach (var d in displays)
            {
                var card = new Grid();
                card.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.2, GridUnitType.Star) });
                card.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
                card.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                var left = new StackPanel { Orientation = Orientation.Horizontal };
                left.Children.Add(new Border
                {
                    Width = 40, Height = 40, CornerRadius = new CornerRadius(8), Background = Ui.Brush("IconGrayBackground"),
                    Child = Ui.Icon("", 18, Ui.Brush("IconGrayForeground")), Margin = new Thickness(0, 0, 12, 0),
                });
                ((FrameworkElement)((Border)left.Children[0]).Child).HorizontalAlignment = HorizontalAlignment.Center;
                var titles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                var name = Ui.Text(Format.OrUnknown(d.Name));
                name.FontWeight = FontWeights.SemiBold;
                name.Margin = new Thickness(0);
                titles.Children.Add(name);
                var kind = (d.Type?.Equals("internal", StringComparison.OrdinalIgnoreCase) == true ? "Built-in" : "External");
                var inches = d.DiagonalInches is { } di && di > 0 ? $"{di}\" " : "";
                titles.Children.Add(Ui.Caption($"{inches}{kind} {DeviceSnapshot.FirstNonEmpty(d.ConnectionType, d.Model) ?? ""}".Trim()));
                left.Children.Add(titles);
                card.Children.Add(left);

                var specs = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                void Spec(string label, string? value, bool copy = false)
                {
                    if (string.IsNullOrWhiteSpace(value)) return;
                    var st = Ui.Stat(label, value, mono: copy, copy: copy);
                    st.Margin = new Thickness(0, 0, 24, 0);
                    specs.Children.Add(st);
                }
                Spec("Resolution", Format.OrUnknown(d.Resolution));
                Spec("Manufacturer", d.Manufacturer);
                Spec("Serial Number", d.SerialNumber, copy: true);
                if (d.ManufactureYear is { } y && y > 0) Spec("Manufactured", d.ManufactureWeek is { } w && w > 0 ? $"Week {w}, {y}" : y.ToString());
                Grid.SetColumn(specs, 1);
                card.Children.Add(specs);

                var badges = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
                if (d.IsMainDisplay) { var b = Ui.Pill("Main Display", Tone.Info); b.Margin = new Thickness(0, 0, 8, 0); badges.Children.Add(b); }
                badges.Children.Add(Ui.Pill(d.Online ? "Connected" : "Disconnected", d.Online ? Tone.Success : Tone.Neutral));
                Grid.SetColumn(badges, 2);
                card.Children.Add(badges);

                var b2 = Ui.Card(card, new Thickness(16, 14, 16, 14));
                if (list.Children.Count > 0) b2.Margin = new Thickness(0, 12, 0, 0);
                list.Children.Add(b2);
            }
            Add(Ui.VStack(Ui.SectionTitle("", "Displays"), list));
        }

        // Storage analysis
        var analysable = (hw.Storage ?? []).Where(d => d.Capacity > 0 && d.RootDirectories is { Count: > 0 }).ToList();
        Add(Ui.VStack(Ui.SectionTitle("", "Storage Analysis"),
            analysable.Count == 0 ? Ui.Card(Ui.EmptyState("Storage analysis data is not available.", "")) : new StorageVisualization(analysable)));

        // Storage devices table
        var drives = (hw.Storage ?? []).Where(d => d.Capacity > 0).ToList();
        if (drives.Count > 0)
        {
            var rows = drives.Select(d =>
            {
                var used = d.Capacity > 0 ? Math.Clamp(Math.Round((d.Capacity - (double)d.FreeSpace) / d.Capacity * 100), 0, 100) : 0;
                return new DriveRow(Format.OrDash(d.Name), Format.OrDash(d.Model), Format.OrDash(d.SerialNumber), Format.OrDash(d.Type),
                    Format.Bytes(d.Capacity), d.FreeSpace > 0 ? $"{Format.Bytes(d.FreeSpace)} ({100 - used}% free)" : "-", used,
                    "-", Format.OrUnknown(d.Health) == "Unknown" ? "" : d.Health,
                    d.Health switch { "Good" or "Healthy" or "OK" => Tone.Success, "Warning" => Tone.Warning, _ => Tone.Error }, Format.OrDash(d.Interface));
            }).ToList();
            Add(Ui.VStack(Ui.SectionTitle("", "Storage Devices"), Table.Card("", null, rows, null, "",
                Col.Text("Name", "Name", 90),
                Col.Text("Model", "Model", 220),
                Col.Text("Serial Number", "Serial", 170, mono: true),
                Col.Text("Type", "Type", 90),
                Col.Text("Capacity", "Capacity", 100),
                Col.Bar("Free Space", "Free", "UsedPercent", 190),
                Col.Pill("Health", "Health", "HealthTone", 90),
                Col.Text("Interface", "Interface", star: true))));
        }

        // Battery
        if (hasBattery)
        {
            var b = battery!;
            var cycleBar = new StackPanel();
            cycleBar.Children.Add(Ui.Text($"{b.CycleCount} / 1000"));
            cycleBar.Children.Add(Ui.UsageBar(Math.Min(b.CycleCount / 10.0, 100)));
            Add(Ui.VStack(Ui.SectionTitle("", "Battery Information"), Ui.Card(Ui.TileRow(12,
                Ui.Tile("Status", b.IsCharging ? "Charging" : "Not Charging"),
                Ui.Tile("Health", Format.OrUnknown(b.Health)),
                b.CycleCount > 0 ? Ui.Tile("Cycle Count", "", cycleBar) : null,
                b.ChargePercent > 0 ? Ui.Tile("Charge", $"{b.ChargePercent}%") : null,
                b.EstimatedRuntime is { } rt && rt.TotalMinutes > 0 ? Ui.Tile("Runtime", $"{(int)rt.TotalMinutes} min") : null), new Thickness(16))));
        }

        // Memory modules
        if (memory?.Modules is { Count: > 0 } modules)
        {
            var rows = modules.Select((m, i) => new ModuleRow(
                string.IsNullOrWhiteSpace(m.Location) ? $"Slot {i + 1}" : m.Location, Format.OrDash(m.Type),
                Format.Bytes(m.Capacity), m.Speed > 0 ? $"{m.Speed} MHz" : "-", Format.OrDash(m.Manufacturer))).ToList();
            Add(Ui.VStack(Ui.SectionTitle("", "Memory Modules"), Table.Card("", null, rows, null, "",
                Col.Text("Location", "Location", 200),
                Col.Text("Type", "Type", 120),
                Col.Text("Capacity", "Capacity", 120),
                Col.Text("Speed", "Speed", 120),
                Col.Text("Manufacturer", "Manufacturer", star: true))));
        }

        // Power plan and thermal
        if (hw.PowerPlan is { } plan && !string.IsNullOrWhiteSpace(plan.Name))
        {
            Add(Ui.VStack(Ui.SectionTitle("", "Power"), Ui.Card(Ui.TileRow(12,
                Ui.Tile("Active Power Plan", plan.Name, plan.IsStandard ? Ui.Pill("Standard plan", Tone.Neutral) : Ui.Pill("Custom plan", Tone.Info)),
                Ui.Tile("Plan GUID", plan.Guid, mono: true)), new Thickness(16))));
        }

        return page;
    }
}

/// <summary>
/// Port of the web StorageVisualization: drive picker, donut of root directories,
/// capacity stats, and a size-sorted, expandable directory tree.
/// </summary>
public sealed class StorageVisualization : ContentControl
{
    private readonly List<StorageDevice> _devices;
    private int _selected;
    private readonly HashSet<string> _expanded = new(StringComparer.OrdinalIgnoreCase);
    private const int MaxDepth = 4;

    public StorageVisualization(List<StorageDevice> devices)
    {
        _devices = devices;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        Render();
    }

    private void Render()
    {
        var device = _devices[Math.Clamp(_selected, 0, _devices.Count - 1)];
        var dirs = (device.RootDirectories ?? []).OrderByDescending(d => d.Size).ToList();
        var used = Math.Max(0, device.Capacity - device.FreeSpace);
        var usedPct = device.Capacity > 0 ? (int)Math.Round(used * 100.0 / device.Capacity) : 0;

        var root = new StackPanel();
        if (_devices.Count > 1)
        {
            root.Children.Add(Ui.Segmented(_devices.Select((d, i) => (i.ToString(), d.Name ?? $"Drive {i + 1}")), _selected.ToString(),
                key => { _selected = int.Parse(key); Render(); }));
            root.Children[^1].SetValue(MarginProperty, new Thickness(0, 0, 0, 12));
        }

        var layout = new Grid();
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(24) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        // Left: overview
        var left = new StackPanel();
        left.Children.Add(Ui.SectionHeader("Storage Analysis"));
        left.Children.Add(Ui.Caption($"{device.Name} {device.Type} {Format.Bytes(device.Capacity, 1)} Total"));
        var health = Ui.Row("Drive Overview", Ui.Pill($"{Format.OrUnknown(device.Health)} Health", device.Health is "Good" or "Healthy" or "OK" ? Tone.Success : Tone.Warning));
        health.Margin = new Thickness(0, 10, 0, 4);
        left.Children.Add(health);
        var donut = Ui.Donut(dirs.Select(d => (Value: (double)d.Size, Brush: Ui.CategoryBrush(d.Category.ToString(), d.Name), Tip: $"{d.Name}: {Format.Bytes(d.Size, 1)}")),
            device.Capacity, $"{usedPct}%", "Used");
        donut.Margin = new Thickness(0, 8, 0, 12);
        donut.HorizontalAlignment = HorizontalAlignment.Center;
        left.Children.Add(donut);
        left.Children.Add(Ui.Row("Capacity", Format.Bytes(device.Capacity, 1)));
        left.Children.Add(Ui.Row("Used", Format.Bytes(used, 1)));
        left.Children.Add(Ui.Row("Free", Format.Bytes(device.FreeSpace, 1)));
        left.Children.Add(Ui.Row("Usage", $"{usedPct}%"));
        if (device.LastAnalyzed is not null) left.Children.Add(Ui.Row("Analyzed", Format.RelativeTime(device.LastAnalyzed), semibold: false));
        layout.Children.Add(left);

        // Right: directory tree
        var right = new StackPanel();
        var header = new Grid();
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var titles = new StackPanel();
        titles.Children.Add(Ui.SectionHeader("Directory Breakdown"));
        titles.Children.Add(Ui.Caption($"{dirs.Count} root directories, sorted by size. Click a directory to expand it."));
        header.Children.Add(titles);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        var expandAll = new Button { Content = "Expand All", Padding = new Thickness(8, 3, 8, 3) };
        expandAll.Click += (_, _) => { foreach (var p in AllPaths(dirs)) _expanded.Add(p); Render(); };
        var collapseAll = new Button { Content = "Collapse All", Padding = new Thickness(8, 3, 8, 3), Margin = new Thickness(6, 0, 0, 0) };
        collapseAll.Click += (_, _) => { _expanded.Clear(); Render(); };
        buttons.Children.Add(expandAll);
        buttons.Children.Add(collapseAll);
        Grid.SetColumn(buttons, 1);
        header.Children.Add(buttons);
        right.Children.Add(header);
        var tree = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
        foreach (var d in dirs) AddNode(tree, d, 0);
        right.Children.Add(tree);
        Grid.SetColumn(right, 2);
        layout.Children.Add(right);

        root.Children.Add(layout);
        Content = Ui.Card(root, new Thickness(20, 16, 20, 20));
    }

    private void AddNode(StackPanel host, DirectoryInformation dir, int level)
    {
        var children = (dir.Subdirectories ?? []).OrderByDescending(d => d.Size).ToList();
        var canExpand = children.Count > 0 && level < MaxDepth;
        var isOpen = _expanded.Contains(dir.Path ?? "");

        var row = new Grid { Margin = new Thickness(level * 22, 0, 0, 0) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(22) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.Children.Add(Ui.Icon(canExpand ? (isOpen ? "" : "") : "", 11, Ui.Brush("TextSecondaryBrush")));
        var names = new StackPanel();
        var name = Ui.Text(dir.Name);
        name.FontWeight = FontWeights.Medium;
        name.Margin = new Thickness(0);
        name.Foreground = Ui.CategoryBrush(dir.Category.ToString(), dir.Name);
        names.Children.Add(name);
        var path = Ui.Caption(dir.Path);
        path.TextTrimming = TextTrimming.CharacterEllipsis;
        path.TextWrapping = TextWrapping.NoWrap;
        names.Children.Add(path);
        Grid.SetColumn(names, 1);
        row.Children.Add(names);
        var sizes = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };
        var size = Ui.Text(Format.Bytes(dir.Size, 1));
        size.FontWeight = FontWeights.SemiBold;
        size.TextAlignment = TextAlignment.Right;
        size.Margin = new Thickness(0);
        sizes.Children.Add(size);
        var pct = Ui.Caption($"{dir.PercentageOfDrive:F1}% of drive");
        pct.TextAlignment = TextAlignment.Right;
        sizes.Children.Add(pct);
        Grid.SetColumn(sizes, 2);
        row.Children.Add(sizes);

        var border = new Border { Padding = new Thickness(8, 6, 8, 6), CornerRadius = new CornerRadius(6), Child = row, Cursor = canExpand ? Cursors.Hand : Cursors.Arrow, Background = System.Windows.Media.Brushes.Transparent };
        if (canExpand)
        {
            var captured = dir.Path ?? "";
            border.MouseLeftButtonUp += (_, _) => { if (!_expanded.Remove(captured)) _expanded.Add(captured); Render(); };
            border.MouseEnter += (_, _) => border.Background = Ui.Brush("SubtleFillBrush");
            border.MouseLeave += (_, _) => border.Background = System.Windows.Media.Brushes.Transparent;
        }
        host.Children.Add(border);
        if (isOpen && canExpand)
            foreach (var child in children) AddNode(host, child, level + 1);
    }

    private static IEnumerable<string> AllPaths(IEnumerable<DirectoryInformation> dirs)
    {
        foreach (var d in dirs)
        {
            if (!string.IsNullOrEmpty(d.Path)) yield return d.Path;
            foreach (var p in AllPaths(d.Subdirectories ?? [])) yield return p;
        }
    }
}
