#
# Copyright (C) 2011-2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# The newer version has different dependency tracking

include $(TOPDIR)/rules.mk

PKG_NAME:=duf
PKG_VERSION:=0.6.0
PKG_RELEASE:=1
PKG_GOGET:=github.com/muesli/duf

GOPKG_SOURCE=GO_$(PKG_NAME)-$(PKG_VERSION)-$(PKG_RELEASE).tar.bz2

#!!! uncomment PKG_SOURCE to download fixed version
#PKG_SOURCE:=$(GOPKG_SOURCE)
PKG_HASH:=skip
PKG_COMMIT:=b59d1d261c56041565a7796f6e1eb74512965af9

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/golang.mk

ifeq ($(BUILD_VARIANT),nohf)
GOARM=GOARM=5
endif

define Package/duf/Default
	$(call Package/gopackage/Default)
	TITLE:=Disk Usage/Free Utility
	URL:=https://github.com/muesli/duf
endef

define Package/duf
	$(call Package/duf/Default)
	VARIANT:=hf
endef

define Package/duf_nohf
	$(call Package/duf/Default)
	VARIANT:=nohf
	DEPENDS:=@(TARGET_armv7_2_6||TARGET_armv7_3_2)
endef

define Package/duf/description
 Disk Usage/Free Utility - a better 'df' alternative
endef

Package/duf_nohf/description=$(Package/duf/description)

define Build/Compile
        (\
                cd $(PKG_BUILD_DIR); \
		mkdir -p bin; \
		cd src/$(PKG_GOGET); \
		CGO_ENABLED=0 GO111MODULE=on GOOS=linux GOARCH=$(GOARCH) $(GOARM) GOPATH=$(PKG_BUILD_DIR) $(GOROOT)/bin/go build -ldflags="-s -w" -x -v; \
		cp duf $(PKG_BUILD_DIR)/bin; \
		chmod -R +w $(PKG_BUILD_DIR)/pkg; \
        )
endef


define Package/duf/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/duf $(1)/opt/bin
endef

Package/duf_nohf/install=$(Package/duf/install)

$(eval $(call BuildPackage,duf))
$(eval $(call BuildPackage,duf_nohf))

