# Copyright (C) 2026 zhz8888/luci-app-komari-agent-c Contributors
# Licensed under MIT License

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for Komari Agent
LUCI_DESCRIPTION:=LuCI web interface for Komari Agent configuration and monitoring.
LUCI_DEPENDS:=+komari-agent-c +luci-base
LUCI_PKGARCH:=all

PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
LUCI_MAINTAINER:=zhz8888

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
