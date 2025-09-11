# EchoStream Modular Structure

The original `api_call.c` file has been successfully modularized into separate files based on functionality. Here's the breakdown:

## File Structure

### Main Files
- **`main.c`** - Main application entry point and coordination
- **`echostream.h`** - Main header with common includes and global state

### Module Files

#### Audio Module
- **`audio.h`** - Audio processing structures and function declarations
- **`audio.c`** - Audio processing implementation
  - PortAudio initialization and management
  - Opus encoding/decoding
  - Jitter buffer management
  - Audio stream callbacks
  - USB device auto-assignment

#### WebSocket Module
- **`websocket.h`** - WebSocket structures and function declarations
- **`websocket.c`** - WebSocket implementation
  - WebSocket client connection
  - Message parsing and handling
  - Event transmission
  - Connection management

#### GPIO Module
- **`gpio.h`** - GPIO structures and function declarations
- **`gpio.c`** - GPIO implementation
  - GPIO pin initialization
  - Pin state monitoring
  - GPIO worker thread
  - Pin cleanup

#### UDP Module
- **`udp.h`** - UDP structures and function declarations
- **`udp.c`** - UDP implementation
  - UDP socket management
  - Heartbeat worker
  - UDP listener worker
  - Message handling

#### Crypto Module
- **`crypto.h`** - Cryptographic function declarations
- **`crypto.c`** - Cryptographic implementation
  - Base64 encoding/decoding
  - AES-256-GCM encryption/decryption

#### Config Module
- **`config.h`** - Configuration function declarations
- **`config.c`** - Configuration implementation
  - JSON configuration loading
  - Channel ID management

## Benefits of Modularization

1. **Separation of Concerns**: Each module handles a specific aspect of the application
2. **Maintainability**: Easier to locate and modify specific functionality
3. **Reusability**: Modules can be reused in other projects
4. **Testing**: Individual modules can be tested independently
5. **Collaboration**: Multiple developers can work on different modules simultaneously
6. **Code Organization**: Clear structure makes the codebase more readable

## Compilation

The updated `Makefile` now compiles all modules into a single executable:

```bash
make clean
make
```

This will create the `echostream` executable from all the modular source files.

## Dependencies

Each module includes only the necessary headers and has clear interfaces defined in their respective header files. The main `echostream.h` file contains common includes and global state that all modules need access to.

## Global State Management

Global variables are properly declared in headers and defined in the appropriate module files, maintaining the same functionality as the original monolithic file while providing better organization.
