#nullable enable
using System;
using System.Collections.Generic;

namespace ReportMate.WindowsClient.Models.Modules
{
    /// <summary>
    /// Comprehensive display module data model
    /// </summary>
    public class DisplayData : BaseModuleData
    {
        public DisplayData()
        {
            Displays = new List<DisplayDevice>();
            DisplayAdapters = new List<DisplayAdapter>();
            DisplaySettings = new DisplayConfiguration();
            ColorProfiles = new List<ColorProfile>();
        }

        /// <summary>
        /// Individual display devices (monitors)
        /// </summary>
        public List<DisplayDevice> Displays { get; set; }

        /// <summary>
        /// Display adapters (graphics cards driving displays)
        /// </summary>
        public List<DisplayAdapter> DisplayAdapters { get; set; }

        /// <summary>
        /// Overall display configuration and settings
        /// </summary>
        public DisplayConfiguration DisplaySettings { get; set; }

        /// <summary>
        /// Color profiles associated with displays
        /// </summary>
        public List<ColorProfile> ColorProfiles { get; set; }
    }

    /// <summary>
    /// Individual display device information
    /// </summary>
    public class DisplayDevice
    {
        public DisplayDevice()
        {
            SupportedResolutions = new List<Resolution>();
            SupportedRefreshRates = new List<int>();
            Capabilities = new List<string>();
        }

        // Basic Information
        public string Name { get; set; } = string.Empty;
        public string DeviceId { get; set; } = string.Empty;
        public string DeviceKey { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string DeviceString { get; set; } = string.Empty;
        
        // Connection and Type
        public string ConnectionType { get; set; } = string.Empty; // HDMI, DisplayPort, USB-C, VGA, DVI, etc.
        public bool IsInternal { get; set; } = false;
        public bool IsExternal { get; set; } = false;
        public bool IsPrimary { get; set; } = false;
        public bool IsActive { get; set; } = false;
        public bool IsEnabled { get; set; } = false;
        
        // Physical Properties
        public double DiagonalSizeInches { get; set; } = 0.0;
        public int WidthMm { get; set; } = 0;
        public int HeightMm { get; set; } = 0;
        public double AspectRatio { get; set; } = 0.0;
        
        // Current Display Settings
        public Resolution CurrentResolution { get; set; } = new Resolution();
        public int CurrentRefreshRate { get; set; } = 0;
        public int CurrentColorDepth { get; set; } = 0;
        public int CurrentDpi { get; set; } = 0;
        public double CurrentScaling { get; set; } = 1.0;
        public string CurrentOrientation { get; set; } = string.Empty; // Landscape, Portrait, etc.
        
        // Supported Capabilities
        public Resolution MaxResolution { get; set; } = new Resolution();
        public Resolution MinResolution { get; set; } = new Resolution();
        public List<Resolution> SupportedResolutions { get; set; }
        public List<int> SupportedRefreshRates { get; set; }
        public int MaxColorDepth { get; set; } = 0;
        public List<string> Capabilities { get; set; }
        
        // Color and Quality
        public string ColorSpace { get; set; } = string.Empty;
        public double Gamma { get; set; } = 0.0;
        public int Brightness { get; set; } = 0;
        public int Contrast { get; set; } = 0;
        
        // Position and Layout
        public int PositionX { get; set; } = 0;
        public int PositionY { get; set; } = 0;
        public int DisplayIndex { get; set; } = 0;
        
        // Technology and Features
        public string PanelType { get; set; } = string.Empty; // LCD, OLED, LED, etc.
        public bool IsHdr { get; set; } = false;
        public bool IsWideGamut { get; set; } = false;
        public bool IsAdaptiveSync { get; set; } = false; // FreeSync/G-Sync
        public bool IsTouch { get; set; } = false;
        
        // Driver and Firmware
        public string DriverVersion { get; set; } = string.Empty;
        public DateTime? DriverDate { get; set; }
        public string FirmwareVersion { get; set; } = string.Empty;
        
        // EDID Information
        public string EdidManufacturer { get; set; } = string.Empty;
        public string EdidProductCode { get; set; } = string.Empty;
        public int EdidWeekOfManufacture { get; set; } = 0;
        public int EdidYearOfManufacture { get; set; } = 0;
        public string EdidVersion { get; set; } = string.Empty;
        
        // Status and Health
        public string Status { get; set; } = string.Empty;
        public string Health { get; set; } = string.Empty;
        public DateTime? LastConnected { get; set; }
        public TimeSpan? Usage { get; set; }
    }

    /// <summary>
    /// Display adapter (graphics card) information
    /// </summary>
    public class DisplayAdapter
    {
        public DisplayAdapter()
        {
            ConnectedDisplays = new List<string>();
            SupportedModes = new List<string>();
        }

        public string Name { get; set; } = string.Empty;
        public string DeviceId { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string ChipType { get; set; } = string.Empty;
        public string DacType { get; set; } = string.Empty;
        public long MemorySize { get; set; } = 0;
        public string DriverVersion { get; set; } = string.Empty;
        public DateTime? DriverDate { get; set; }
        public string BiosVersion { get; set; } = string.Empty;
        public List<string> ConnectedDisplays { get; set; }
        public List<string> SupportedModes { get; set; }
        public int MaxDisplays { get; set; } = 0;
        public bool Is3dCapable { get; set; } = false;
        public bool IsHardwareAccelerated { get; set; } = false;
    }

    /// <summary>
    /// Overall display configuration
    /// </summary>
    public class DisplayConfiguration
    {
        public DisplayConfiguration()
        {
            Displays = new List<DisplayLayoutInfo>();
        }

        public int TotalDisplays { get; set; } = 0;
        public int ActiveDisplays { get; set; } = 0;
        public string PrimaryDisplay { get; set; } = string.Empty;
        public string DisplayMode { get; set; } = string.Empty; // Extend, Duplicate, Single, etc.
        public List<DisplayLayoutInfo> Displays { get; set; }
        
        // Global Settings
        public bool IsExtendedDesktop { get; set; } = false;
        public bool IsMirroredDesktop { get; set; } = false;
        public int VirtualDesktopWidth { get; set; } = 0;
        public int VirtualDesktopHeight { get; set; } = 0;
        
        // Power Management
        public int DisplaySleepTimeout { get; set; } = 0; // Minutes
        public bool IsPowerSavingEnabled { get; set; } = false;
        
        // Accessibility
        public bool IsHighContrastEnabled { get; set; } = false;
        public double TextScaling { get; set; } = 1.0;
        public bool IsMagnifierEnabled { get; set; } = false;
    }

    /// <summary>
    /// Display layout and positioning information
    /// </summary>
    public class DisplayLayoutInfo
    {
        public string DisplayName { get; set; } = string.Empty;
        public int X { get; set; } = 0;
        public int Y { get; set; } = 0;
        public int Width { get; set; } = 0;
        public int Height { get; set; } = 0;
        public bool IsPrimary { get; set; } = false;
        public string Orientation { get; set; } = string.Empty;
    }

    /// <summary>
    /// Display resolution information
    /// </summary>
    public class Resolution
    {
        public int Width { get; set; } = 0;
        public int Height { get; set; } = 0;
        public string DisplayName => $"{Width}x{Height}";
        public double AspectRatio => Height > 0 ? (double)Width / Height : 0.0;
        
        public override string ToString() => DisplayName;
        
        public override bool Equals(object? obj)
        {
            if (obj is Resolution other)
                return Width == other.Width && Height == other.Height;
            return false;
        }
        
        public override int GetHashCode() => HashCode.Combine(Width, Height);
    }

    /// <summary>
    /// Color profile information
    /// </summary>
    public class ColorProfile
    {
        public string Name { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string ColorSpace { get; set; } = string.Empty;
        public string DeviceModel { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public bool IsDefault { get; set; } = false;
        public DateTime? CreatedDate { get; set; }
        public long FileSize { get; set; } = 0;
    }
}
