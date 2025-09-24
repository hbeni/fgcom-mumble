# Build Configuration Options

## jsimconnect Integration Toggle

The fgcom-mumble radioGUI can be built with or without jsimconnect support, depending on your needs.

### What is jsimconnect?

jsimconnect provides integration with Microsoft Flight Simulator 2020 (MSFS2020) for:
- Real-time aircraft position data
- Automatic radio frequency management
- Flight simulation integration

### When to use each option:

#### **With jsimconnect** (Default: `ENABLE_JSIMCONNECT=true`)
- **Use when**: You want MSFS2020 integration
- **Use when**: You need automatic aircraft position tracking
- **Use when**: You want radio frequencies synced with flight simulator
- **Don't use when**: You only need standalone radio simulation
- **Don't use when**: You're using other clients (like supermorse-web)

#### **Without jsimconnect** (Set: `ENABLE_JSIMCONNECT=false`)
- **Use when**: You only need standalone radio simulation
- **Use when**: You're using other Mumble clients (supermorse-web, etc.)
- **Use when**: You don't have MSFS2020
- **Use when**: You want smaller JAR file (663KB vs 789KB)
- **Don't use when**: You need MSFS2020 integration

## Build Commands

### Default build (with jsimconnect):
```bash
make build-radioGUI
```

### Build without jsimconnect:
```bash
make build-radioGUI-without-jsimconnect
# OR
make build-radioGUI ENABLE_JSIMCONNECT=false
```

### Build with jsimconnect (explicit):
```bash
make build-radioGUI-with-jsimconnect
# OR
make build-radioGUI ENABLE_JSIMCONNECT=true
```

## File Size Comparison

| Configuration | JAR Size | Use Case |
|---------------|----------|----------|
| With jsimconnect | 789KB | MSFS2020 integration |
| Without jsimconnect | 663KB | Standalone radio simulation |

## For supermorse-web Users

If you're planning to use supermorse-web or other direct Mumble clients, you should build without jsimconnect:

```bash
make build-radioGUI-without-jsimconnect
```

This will:
- Skip jsimconnect compilation
- Create smaller JAR file
- Still provide full radio simulation features
- Work perfectly with supermorse-web and other Mumble clients
