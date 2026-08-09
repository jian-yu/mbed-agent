include $(TOPDIR)/rules.mk

PKG_NAME:=mbed-agent
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/mbed-agent
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Resource-bounded Linux/OpenWrt network agent
  URL:=https://github.com/jian-yu/mbed-agent
  DEPENDS:=+ca-bundle
endef

define Package/mbed-agent/description
  A Rust network operations agent for OpenWrt 21.02+ and embedded Linux.
  The package consumes a target-architecture binary supplied by the release
  pipeline and never invokes cargo or a network service from the router.
endef

define Package/mbed-agent/conffiles
/etc/config/mbed-agent
/etc/mbed-agent/config.toml
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./files $(PKG_BUILD_DIR)/
endef

define Build/Compile
	[ -n "$(MBED_AGENT_BINARY)" ] || { \
		echo "MBED_AGENT_BINARY must point to a target-architecture mbed-agent binary" >&2; \
		exit 1; \
	}
	[ -f "$(MBED_AGENT_BINARY)" ] || { \
		echo "MBED_AGENT_BINARY does not name a regular file" >&2; \
		exit 1; \
	}
	$(INSTALL_BIN) "$(MBED_AGENT_BINARY)" "$(PKG_BUILD_DIR)/mbed-agent"
endef

define Package/mbed-agent/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mbed-agent $(1)/usr/sbin/mbed-agent
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config $(1)/etc/mbed-agent
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/mbed-agent $(1)/etc/init.d/mbed-agent
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/files/etc/config/mbed-agent $(1)/etc/config/mbed-agent
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/files/etc/mbed-agent/config.toml $(1)/etc/mbed-agent/config.toml
endef

$(eval $(call BuildPackage,mbed-agent))
