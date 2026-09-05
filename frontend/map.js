/**
 * AegisMail Forensics AI — Leaflet Map Module
 * Handles geolocation map rendering for relay trace visualization.
 */

let mapInstance = null;
let mapMarkers = [];
let mapPolyline = null;

function initMap(containerId) {
  const el = document.getElementById(containerId || 'geolocation-map');
  if (!el || typeof L === 'undefined') return;

  // Destroy existing instance if any
  if (mapInstance) {
    mapInstance.remove();
    mapInstance = null;
    mapMarkers = [];
    mapPolyline = null;
  }

  mapInstance = L.map(el, {
    zoomControl: true,
    attributionControl: false
  }).setView([30, 20], 2);

  L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
    maxZoom: 19,
    subdomains: 'abcd'
  }).addTo(mapInstance);

  // Ensure map renders correctly after container is visible
  setTimeout(() => {
    if (mapInstance) mapInstance.invalidateSize();
  }, 200);
}

function updateMapMarkers(relays) {
  if (!mapInstance || typeof L === 'undefined') return;

  // Clear previous
  mapMarkers.forEach(m => mapInstance.removeLayer(m));
  mapMarkers = [];
  if (mapPolyline) {
    mapInstance.removeLayer(mapPolyline);
    mapPolyline = null;
  }

  // Filter relays that have valid coordinates
  const validRelays = relays.filter(r => r.lat && r.lng && (r.lat !== 0 || r.lng !== 0));
  if (validRelays.length === 0) return;

  const latLngs = [];

  validRelays.forEach((hop, idx) => {
    const isEarliest = idx === 0;
    const isDestination = idx === validRelays.length - 1;

    const color = isEarliest ? '#E11D48' : isDestination ? '#059669' : '#2563EB';

    const iconHtml = `
      <div style="
        width: 22px; height: 22px; border-radius: 50%;
        background: ${color};
        border: 2.5px solid #FFFFFF;
        box-shadow: 0 2px 6px rgba(0,0,0,0.25);
        display: flex; align-items: center; justify-content: center;
        font-size: 10px; font-weight: bold; color: #fff;
      ">${hop.hop}</div>
    `;

    const customIcon = L.divIcon({
      html: iconHtml,
      className: 'custom-map-icon',
      iconSize: [20, 20],
      iconAnchor: [10, 10]
    });

    const marker = L.marker([hop.lat, hop.lng], { icon: customIcon })
      .bindPopup(`
        <div style="font-family: 'Inter', sans-serif; font-size: 12px; color: #1e293b; line-height: 1.5; max-width: 220px;">
          <strong>Hop #${hop.hop}: ${escapeHtml(hop.host)}</strong><br>
          <span style="font-family: monospace; color: #2563EB;">IP: ${escapeHtml(hop.ip)}</span><br>
          <span>Location: ${escapeHtml(hop.location)}</span><br>
          <span>ISP: ${escapeHtml(hop.isp)}</span><br>
          <span style="color: ${isEarliest ? '#DC2626' : '#059669'}; font-weight: 600;">${escapeHtml(hop.note)}</span>
        </div>
      `)
      .addTo(mapInstance);

    mapMarkers.push(marker);
    latLngs.push([hop.lat, hop.lng]);
  });

  if (latLngs.length > 1) {
    mapPolyline = L.polyline(latLngs, {
      color: '#3B82F6',
      weight: 2.5,
      opacity: 0.7,
      dashArray: '6, 8'
    }).addTo(mapInstance);
  }

  fitMapBounds();
}

function fitMapBounds() {
  if (mapMarkers.length > 0 && mapInstance) {
    const group = new L.featureGroup(mapMarkers);
    mapInstance.fitBounds(group.getBounds().pad(0.3));
  }
}

function refreshMap() {
  if (mapInstance) {
    setTimeout(() => {
      mapInstance.invalidateSize();
      fitMapBounds();
    }, 150);
  }
}

function destroyMap() {
  if (mapInstance) {
    mapInstance.remove();
    mapInstance = null;
    mapMarkers = [];
    mapPolyline = null;
  }
}
