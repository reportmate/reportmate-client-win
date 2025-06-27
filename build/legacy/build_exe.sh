#!/bin/bash

# ReportMate Build Script
# Builds the Windows client executable for distribution

set -e

# Configuration
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$BUILD_DIR/../src"
OUTPUT_DIR="$BUILD_DIR/output"
PUBLISH_DIR="$BUILD_DIR/publish"
NUPKG_DIR="$BUILD_DIR/../nupkg"
PROGRAM_FILES_PAYLOAD_DIR="$NUPKG_DIR/payload/Program Files/ReportMate"
PROGRAM_DATA_PAYLOAD_DIR="$NUPKG_DIR/payload/ProgramData/ManagedReports"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Building ReportMate${NC}"
echo "=================================="

# Clean previous builds
echo -e "${YELLOW}🧹 Cleaning previous builds...${NC}"
rm -rf "$OUTPUT_DIR"
rm -rf "$PUBLISH_DIR"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$PUBLISH_DIR"

# Check prerequisites
echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

if ! command -v dotnet &> /dev/null; then
    echo -e "${RED}❌ .NET SDK not found. Please install .NET 8.0 SDK${NC}"
    exit 1
fi

# Verify .NET version
DOTNET_VERSION=$(dotnet --version)
echo "✅ .NET SDK version: $DOTNET_VERSION"

# Build the application
echo -e "${YELLOW}🔨 Building ReportMate...${NC}"

cd "$PROJECT_DIR"

# Restore dependencies
echo "📦 Restoring NuGet packages..."
dotnet restore

# Build in Release configuration
echo "🏗️  Building Release configuration..."
dotnet build --configuration Release --no-restore

# Publish self-contained executable
echo "📤 Publishing self-contained executable..."
dotnet publish \
    --configuration Release \
    --runtime win-x64 \
    --self-contained true \
    --output "$PUBLISH_DIR" \
    -p:PublishSingleFile=true \
    -p:PublishTrimmed=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -p:AssemblyName=runner

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Build completed successfully!${NC}"
else
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
fi

# Prepare cimipkg payload
echo -e "${YELLOW}📦 Preparing cimipkg payload...${NC}"

# Clean and create payload directories
rm -rf "$PROGRAM_FILES_PAYLOAD_DIR"
rm -rf "$PROGRAM_DATA_PAYLOAD_DIR"
mkdir -p "$PROGRAM_FILES_PAYLOAD_DIR"
mkdir -p "$PROGRAM_DATA_PAYLOAD_DIR"
mkdir -p "$NUPKG_DIR/payload/Program Files/Cimian"

# Copy executable and binaries to Program Files/ReportMate
cp "$PUBLISH_DIR/runner.exe" "$PROGRAM_FILES_PAYLOAD_DIR/"

# Note: No configuration files in Program Files - all configs are in ProgramData for CSP/OMA-URI management

# Create version info file in Program Files
cat > "$PROGRAM_FILES_PAYLOAD_DIR/version.txt" << EOF
ReportMate
Version: $(dotnet --version)
Build Date: $(date)
Platform: Windows x64
EOF

# Copy working configuration and queries to ProgramData
cp "$PROJECT_DIR/appsettings.yaml" "$PROGRAM_DATA_PAYLOAD_DIR/"
cp "$PROJECT_DIR/osquery-queries.json" "$PROGRAM_DATA_PAYLOAD_DIR/queries.json"

# Create enterprise template configuration (CSP/OMA-URI manageable)
cp "$PROJECT_DIR/appsettings.yaml" "$PROGRAM_DATA_PAYLOAD_DIR/appsettings.template.yaml"

# Ensure Cimian postflight script is in place (it should already exist in the repo)
if [ ! -f "$NUPKG_DIR/payload/Program Files/Cimian/postflight.ps1" ]; then
    echo -e "${YELLOW}⚠️  Cimian postflight script not found, creating placeholder...${NC}"
    cat > "$NUPKG_DIR/payload/Program Files/Cimian/postflight.ps1" << 'EOF'
# ReportMate Cimian Postflight Script
# This script runs after Cimian installation to execute ReportMate
Write-Host "ReportMate Cimian postflight script placeholder"
# Add actual postflight logic here
EOF
fi

echo -e "${GREEN}✅ Payload prepared for cimipkg${NC}"
echo -e "${BLUE}   Program Files: $PROGRAM_FILES_PAYLOAD_DIR${NC}"
echo -e "${BLUE}   ProgramData: $PROGRAM_DATA_PAYLOAD_DIR${NC}"

# Clean up any .DS_Store files (macOS)
find "$NUPKG_DIR" -name ".DS_Store" -delete 2>/dev/null || true

# Create deployment package
echo -e "${YELLOW}📦 Creating deployment package...${NC}"

cd "$PUBLISH_DIR"

# Create version info file
cat > version.txt << EOF
ReportMate
Version: $(dotnet --version)
Build Date: $(date)
Platform: Windows x64
EOF

# Create ZIP package
PACKAGE_NAME="reportmate-windows-client-$(date +%Y%m%d-%H%M%S).zip"
zip -r "$OUTPUT_DIR/$PACKAGE_NAME" .

echo -e "${GREEN}📦 Package created: $OUTPUT_DIR/$PACKAGE_NAME${NC}"

# Display build summary
echo ""
echo -e "${GREEN}🎉 Build Summary${NC}"
echo "================"
echo "Executable: $PUBLISH_DIR/runner.exe"
echo "Package: $OUTPUT_DIR/$PACKAGE_NAME"
echo "Size: $(ls -lh "$OUTPUT_DIR/$PACKAGE_NAME" | awk '{print $5}')"

# Instructions
echo ""
echo -e "${BLUE}📖 Next Steps:${NC}"
echo "1. Test the executable: $PUBLISH_DIR/runner.exe --help"
echo "2. Copy package to deployment server: $OUTPUT_DIR/$PACKAGE_NAME"
echo "3. Create MSI installer using create-installer.ps1"
echo "4. Deploy via Group Policy or Configuration Manager"

echo ""
echo -e "${GREEN}✨ Build completed successfully!${NC}"
