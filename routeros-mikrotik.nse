-- HEAD --
description = [[
Simple port detector for Winbox
]]

author = "Mahyuddin Susanto"

-- RULE --


-- @usage
-- nmap -sV --script routeros-mikrotik.nse
-- @output
-- Starting Nmap 7.60 ( https://nmap.org ) at 2019-11-04 00:32 PST
-- Host is up (0.0015s latency).
-- Not shown: 997 closed ports
-- PORT     STATE SERVICE
-- 8291/tcp open  unknown
-- |_routeros-mikrotik: Winbox Port(s) is Open!
--

local shortport = require "shortport"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "intrusive"}
require "shortport"
portrule = shortport.portnumber(8291, "tcp", "open")

-- ACTION --

action = function(host, port)
	return "Winbox Port is Open!"
end


