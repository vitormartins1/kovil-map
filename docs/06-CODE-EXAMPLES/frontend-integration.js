/**
 * Example: Integrating Spatial Normalization in Frontend Maps
 * 
 * This example shows how to use the new displayLatitude/displayLongitude
 * fields and handle the position metadata when rendering on the map.
 */

// === EXAMPLE 1: Basic Map Rendering ===

async function renderNetworksOnMap() {
    const mapData = await API.getMapData();
    
    for (const [mac, network] of Object.entries(mapData)) {
        // Use displayLatitude/displayLongitude for map rendering
        const lat = network.displayLatitude !== undefined 
            ? network.displayLatitude 
            : network.lat;
        const lng = network.displayLongitude !== undefined 
            ? network.displayLongitude 
            : network.lng;
        
        // Create marker with styling based on position mode
        const markerColor = network.positionMode === 'derived_jitter' 
            ? '#FFB84D'  // Orange for jittered positions
            : '#4CAF50'; // Green for raw positions
        
        L.marker([lat, lng], {
            icon: L.icon({
                iconUrl: `icon-${markerColor}.png`,
                iconSize: [32, 32]
            })
        })
        .addTo(map)
        .bindPopup(createNetworkPopup(network));
    }
}

// === EXAMPLE 2: Enhanced Popup with Raw Data ===

function createNetworkPopup(network) {
    const html = `
        <div class="network-popup">
            <div class="network-header">
                <h3>${network.ssid || '(Hidden)'}</h3>
                <span class="mac">${network.mac}</span>
            </div>
            
            <div class="network-position">
                <strong>Position:</strong>
                <div class="coordinates">
                    <div>Lat: ${network.displayLatitude?.toFixed(6) || 'N/A'}</div>
                    <div>Lng: ${network.displayLongitude?.toFixed(6) || 'N/A'}</div>
                </div>
            </div>
            
            ${network.positionMode === 'derived_jitter' ? `
                <div class="position-notice">
                    <i class="fa-info"></i> Position was derived using jitter 
                    (multiple networks at same GPS point)
                    <details class="raw-coordinates">
                        <summary>Show Raw Coordinates</summary>
                        <div>Raw Lat: ${network.rawLatitude?.toFixed(6)}</div>
                        <div>Raw Lng: ${network.rawLongitude?.toFixed(6)}</div>
                        <div>Distance: ~${calculateDistance(
                            network.rawLatitude, network.rawLongitude,
                            network.displayLatitude, network.displayLongitude
                        ).toFixed(1)}m</div>
                    </details>
                </div>
            ` : ''}
            
            <div class="network-metadata">
                <div><strong>Signal:</strong> ${network.rssi || 'N/A'} dBm</div>
                <div><strong>Accuracy:</strong> ${network.rawAccuracy || 'N/A'} m</div>
                <div><strong>Confidence:</strong> ${network.positionConfidence || 'N/A'}</div>
                <div><strong>Source:</strong> ${formatSourceType(network.sourceType)}</div>
            </div>
            
            ${network.pass ? `
                <div class="cracked">
                    <strong>Password:</strong> ${network.pass}
                </div>
            ` : ''}
        </div>
    `;
    
    return html;
}

// === EXAMPLE 3: Calculate Distance Between Raw and Display ===

function calculateDistance(lat1, lng1, lat2, lng2) {
    // Haversine formula to calculate distance in meters
    const R = 6371000; // Earth's radius in meters
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLng = (lng2 - lng1) * Math.PI / 180;
    
    const a = 
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
        Math.sin(dLng / 2) * Math.sin(dLng / 2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

// === EXAMPLE 4: Filter Networks by Position Mode ===

function filterNetworksByPositionMode(networks, mode) {
    // mode can be: 'raw', 'derived_jitter', 'preferred_external'
    
    return Object.entries(networks)
        .filter(([mac, net]) => net.positionMode === mode)
        .reduce((obj, [mac, net]) => {
            obj[mac] = net;
            return obj;
        }, {});
}

// Usage examples:
const jitteredNetworks = filterNetworksByPositionMode(mapData, 'derived_jitter');
const rawNetworks = filterNetworksByPositionMode(mapData, 'raw');

console.log(`Jittered positions: ${Object.keys(jitteredNetworks).length}`);
console.log(`Raw positions: ${Object.keys(rawNetworks).length}`);

// === EXAMPLE 5: Cluster Visualization ===

function visualizeNetworkClusters(networks) {
    // Group networks by session, raw lat, raw lng to show clusters
    const clusters = new Map();
    
    for (const [mac, network] of Object.entries(networks)) {
        if (!network.rawLatitude || !network.rawLongitude) continue;
        
        const key = `${network.sessionId || 'default'}:${
            network.rawLatitude.toFixed(6)}:${network.rawLongitude.toFixed(6)}`;
        
        if (!clusters.has(key)) {
            clusters.set(key, []);
        }
        clusters.get(key).push(mac);
    }
    
    // Draw circles for clusters with >1 network
    for (const [key, macs] of clusters.entries()) {
        if (macs.length > 1) {
            const network = networks[macs[0]];
            
            // Draw circle at the raw location showing cluster size
            L.circle([network.rawLatitude, network.rawLongitude], {
                radius: 20,
                color: '#FF5252',
                fill: false,
                weight: 2,
                dashArray: '5, 5',
                popup: `Cluster: ${macs.length} networks at this exact GPS point`
            })
            .addTo(map);
            
            console.log(`Cluster at (${network.rawLatitude}, ${network.rawLongitude}): ${macs.length} networks`);
        }
    }
}

// === EXAMPLE 6: Statistics UI ===

function displayPositionStatistics(networks) {
    const stats = {
        total: 0,
        withPosition: 0,
        jittered: 0,
        rawPositions: 0,
        bySource: {}
    };
    
    for (const [mac, network] of Object.entries(networks)) {
        stats.total++;
        
        if (network.lat !== null && network.lng !== null) {
            stats.withPosition++;
        }
        
        if (network.positionMode === 'derived_jitter') {
            stats.jittered++;
        }
        
        if (network.positionMode === 'raw') {
            stats.rawPositions++;
        }
        
        const source = network.sourceType || 'unknown';
        stats.bySource[source] = (stats.bySource[source] || 0) + 1;
    }
    
    // Display statistics
    document.getElementById('stats').innerHTML = `
        <div class="statistics">
            <div class="stat-item">
                <label>Total Networks:</label>
                <value>${stats.total}</value>
            </div>
            <div class="stat-item">
                <label>With Position:</label>
                <value>${stats.withPosition}</value>
            </div>
            <div class="stat-item">
                <label>Jittered Positions:</label>
                <value>${stats.jittered}</value>
                <tooltip>Networks separated due to clustering</tooltip>
            </div>
            <div class="stat-item">
                <label>Raw Positions:</label>
                <value>${stats.rawPositions}</value>
            </div>
            <div class="sources">
                <strong>By Source:</strong>
                ${Object.entries(stats.bySource)
                    .map(([source, count]) => `
                        <div class="source-item">
                            <label>${formatSourceType(source)}:</label>
                            <value>${count}</value>
                        </div>
                    `).join('')}
            </div>
        </div>
    `;
}

// === HELPER FUNCTIONS ===

function formatSourceType(sourceType) {
    const sourceMap = {
        'pwnagotchi-handshake-gps': '🔴 Pwnagotchi GPS (Handshake)',
        'pwnagotchi-wardrive': '🟠 Pwnagotchi Wardrive',
        'bruce-wardriving-csv': '🟡 Bruce CSV',
        'unknown': '⚫ Unknown'
    };
    
    return sourceMap[sourceType] || sourceType;
}

function getConfidenceIcon(confidence) {
    const icons = {
        'high': '⭐⭐⭐',
        'medium': '⭐⭐',
        'low': '⭐'
    };
    
    return icons[confidence] || '?';
}

// === CSS STYLES (for HTML popup) ===

const popupStyles = `
    <style>
        .network-popup {
            font-family: Arial, sans-serif;
            min-width: 250px;
        }
        
        .network-header {
            border-bottom: 2px solid #CCC;
            margin-bottom: 10px;
            padding-bottom: 10px;
        }
        
        .network-header h3 {
            margin: 0;
            color: #333;
        }
        
        .mac {
            font-family: monospace;
            font-size: 12px;
            color: #666;
        }
        
        .coordinates {
            background-color: #F5F5F5;
            padding: 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
        }
        
        .position-notice {
            background-color: #FFF3E0;
            border-left: 4px solid #FFB84D;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            font-size: 13px;
        }
        
        .raw-coordinates {
            margin-top: 8px;
            font-family: monospace;
            font-size: 11px;
        }
        
        .network-metadata {
            margin-top: 10px;
            font-size: 13px;
        }
        
        .cracked {
            background-color: #C8E6C9;
            padding: 8px;
            margin-top: 10px;
            border-radius: 4px;
            color: #2E7D32;
        }
    </style>
`;

// === USAGE ===

// After loading map data:
const mapData = await API.getMapData();

// Render networks with normalized positions
renderNetworksOnMap();

// Show cluster visualization
visualizeNetworkClusters(mapData);

// Display statistics
displayPositionStatistics(mapData);

// Filter operations
const jitteredOnly = filterNetworksByPositionMode(mapData, 'derived_jitter');
console.log(`Found ${Object.keys(jitteredOnly).length} networks with jittered positions`);
