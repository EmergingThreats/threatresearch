# 2022-07-19 - DNS Rule Update Event

## Executive Summary

In an effort to modernize legacy dns rules in the emerging threats ruleset to conform with our rule style guidance,
enhance performance, and utilize Suricata’s enhanced protocol support, a rule update was published on 2022/07/15 with
updates to rules 2014702 and 2014703. The modifications resulted in several customers experiencing false positives. The
root cause of this problem is the result of these rules inspecting DNS over TCP traffic, and analyzing key bytes used to
detect the anomalies at the incorrect offsets. The issue was finally resolved by reverting these rules back to inspect
DNS over UDP port 53 payloads when revision 13 of the rules were released on 2022/07/18. We are also introducing new
rules designed to inspect DNS over TCP payloads at the correct offsets. As a part of lessons learned, Emerging Threat QA
processes are being revised to prevent a repeat of this problem in the future.

Full details can be found within the [detailed writeup.](2022-07-19/README.md)
