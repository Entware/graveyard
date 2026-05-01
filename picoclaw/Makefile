# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2026 Entware
#

include $(TOPDIR)/rules.mk

PKG_NAME:=picoclaw
PKG_VERSION:=0.2.8
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/sipeed/picoclaw
#PKG_MIRROR_HASH:=f5cebc176968a0734c7123f8286f4600277d827328dda1394826ea8867b5790f

PKG_MAINTAINER:=Entware team, https://entware.net

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/golang.mk

define Package/picoclaw/Default
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Ultra-Efficient AI Assistant
  URL:=https://picoclaw.io/
endef

define Package/picoclaw
  $(call Package/picoclaw/Default)
  VARIANT:=hf
  DEFAULT_VARIANT:=1
endef

define Package/picoclaw_nohf
  $(call Package/picoclaw/Default)
  VARIANT:=nohf
  DEPENDS:=@arm
endef

define Package/picoclaw/description
 Tiny, Fast, and Deployable anywhere — automate the mundane,
 unleash your creativity.
endef

Package/picoclaw_nohf/description=$(Package/picoclaw/description)

GO_TAGS:=goolm, stdjson
GO_TARGET:=./cmd/picoclaw
CONFIG_PKG=github.com/sipeed/picoclaw/pkg/config
GO_LDFLAGS +=-X $(CONFIG_PKG).Version=dev -X $(CONFIG_PKG).GitCommit=dev -X $(CONFIG_PKG).BuildTime=dev -X $(CONFIG_PKG).GoVersion=unknown


define Build/Compile
	( cd $(PKG_BUILD_DIR); \
		$(GO_BIN_GENERATE) ./...; \
	)
	$(call Build/Compile/Go)
endef

define Package/picoclaw/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/picoclaw $(1)/opt/bin
endef

Package/picoclaw_nohf/install=$(Package/picoclaw/install)

$(eval $(call BuildPackage,picoclaw))
$(eval $(call BuildPackage,picoclaw_nohf))
