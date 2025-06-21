CC = clang
CFLAGS = -Wall -Wextra -Werror -fPIC -DPIC -O2 -std=c23
LDFLAGS = -shared -Wl,-x
LIBS = -lpam -lbluetooth

SOURCE = lib.c
TARGET = pam_bluetooth.so

PAM_MODULE_DIR = /usr/lib/security
CONFIG_DIR = /etc

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@echo "Installing PAM module..."
	sudo cp $(TARGET) $(PAM_MODULE_DIR)/
	sudo chmod 755 $(PAM_MODULE_DIR)/$(TARGET)
	@echo "Creating default config file..."
	@if [ ! -f $(CONFIG_DIR)/pam_bluetooth.conf ]; then \
		sudo cp pam_bluetooth.conf $(CONFIG_DIR)/pam_bluetooth.conf; \
		sudo chmod 644 $(CONFIG_DIR)/pam_bluetooth.conf; \
		echo "Config file created at $(CONFIG_DIR)/pam_bluetooth.conf"; \
		echo "Please edit it with your device MAC address!"; \
	else \
		echo "Config file already exists at $(CONFIG_DIR)/pam_bluetooth.conf"; \
	fi

uninstall:
	sudo rm -f $(PAM_MODULE_DIR)/$(TARGET)
	@echo "PAM module removed. Config file left intact."

debug: CFLAGS += -ggdb -DDEBUG
debug: $(TARGET)

test-config:
	@echo "Testing config file parsing..."
	@if [ -f $(CONFIG_DIR)/pam_bluetooth.conf ]; then \
		echo "Config file exists:"; \
		cat $(CONFIG_DIR)/pam_bluetooth.conf; \
	else \
		echo "No config file found at $(CONFIG_DIR)/pam_bluetooth.conf"; \
	fi

check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists bluez && echo "✓ BlueZ development files found" || echo "✗ Install libbluetooth-dev"
	@ldconfig -p | grep -q libpam && echo "✓ PAM library found" || echo "✗ Install libpam0g-dev"
