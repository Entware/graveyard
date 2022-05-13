#
# Copyright (C) 2011-2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Works fine, but useless for me now

include $(TOPDIR)/rules.mk

PKG_NAME:=wgcf
PKG_VERSION:=2.2.14
PKG_RELEASE:=1
PKG_GOGET:=github.com/ViRb3/wgcf

GOPKG_SOURCE=GO_$(PKG_NAME)-$(PKG_VERSION)-$(PKG_RELEASE).tar.bz2

#!!! uncomment PKG_SOURCE to download fixed version
#PKG_SOURCE:=$(GOPKG_SOURCE)
PKG_HASH:=skip
PKG_COMMIT:=5a3455aec186fa69dfd05b03bebe7141af209967

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/golang.mk

ifeq ($(BUILD_VARIANT),nohf)
GOARM=GOARM=5
endif

define Package/wgcf/Default
	$(call Package/gopackage/Default)
	TITLE:=unofficial CLI for Cloudflare Warp
	URL:=https://github.com/ViRb3/wgcf
	DEPENDS:=@!LINUX_2_6_36
endef

define Package/wgcf
	$(call Package/wgcf/Default)
	VARIANT:=hf
endef

define Package/wgcf_nohf
	$(call Package/wgcf/Default)
	VARIANT:=nohf
	DEPENDS:=@TARGET_armv7_3_2
endef

define Package/wgcf/description
 Cross-platform, unofficial CLI for Cloudflare Warp.
endef

Package/wgcf_nohf/description=$(Package/wgcf/description)

define Build/Compile
        (\
		cd $(PKG_BUILD_DIR); \
		mkdir -p bin; \
		cd src/$(PKG_GOGET); \
		CGO_ENABLED=0 GO111MODULE=on GOOS=linux GOARCH=$(GOARCH) $(GOARM) GOPATH=$(PKG_BUILD_DIR) $(GOROOT)/bin/go build -ldflags="-X main.version=$(PKG_VERSION) -s -w" -x -v $(PKG_GOGET); \
		chmod -R +w $(PKG_BUILD_DIR)/pkg; \
        )
endef


define Package/wgcf/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/$(PKG_GOGET)/wgcf $(1)/opt/bin
endef

Package/wgcf_nohf/install=$(Package/wgcf/install)

$(eval $(call BuildPackage,wgcf))
$(eval $(call BuildPackage,wgcf_nohf))

