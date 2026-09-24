import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

import markerIcon2x from "leaflet/dist/images/marker-icon-2x.png";
import markerIcon from "leaflet/dist/images/marker-icon.png";
import markerShadow from "leaflet/dist/images/marker-shadow.png";

L.Icon.Default.mergeOptions({
  iconRetinaUrl: markerIcon2x,
  iconUrl: markerIcon,
  shadowUrl: markerShadow,
});

function isValidCoordinate(value) {
  return value !== null && value !== undefined && Number.isFinite(Number(value));
}

function MapViewport({ points }) {
  const map = useMap();

  if (points.length === 1) {
    map.setView([points[0].latitude, points[0].longitude], 5);
  } else if (points.length > 1) {
    const bounds = L.latLngBounds(
      points.map((point) => [point.latitude, point.longitude])
    );
    map.fitBounds(bounds, { padding: [40, 40] });
  }

  return null;
}

export default function GeoLocationMap({ results = [] }) {
  const points = results
    .map((item) => ({
      ...item,
      latitude: Number(item.latitude),
      longitude: Number(item.longitude),
    }))
    .filter(
      (item) =>
        isValidCoordinate(item.latitude) &&
        isValidCoordinate(item.longitude) &&
        item.latitude >= -90 &&
        item.latitude <= 90 &&
        item.longitude >= -180 &&
        item.longitude <= 180
    )
    .filter((item) => {
      const ip  = String(item.ip || "");
      const addressType = String(item.address_type || item.type || "").toUpperCase();
      return (
        ip &&
        !["PRIVATE", "RESERVED", "DOCUMENTATION", "INVALID", "NON_ROUTABLE"].includes(addressType)
      );
    });

  return (
    <section
      style={{
        marginTop: "22px",
        padding: "16px",
        border: "1px solid rgba(0, 220, 255, 0.16)",
        borderRadius: "14px",
        background: "rgba(0, 12, 24, 0.62)",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "12px",
          marginBottom: "12px",
          flexWrap: "wrap",
        }}
      >
        <div>
          <span
            style={{
              display: "block",
              fontSize: "10px",
              letterSpacing: "1.8px",
              opacity: 0.55,
              marginBottom: "5px",
            }}
          >
            ORIGIN VISUALIZATION
          </span>
          <h3 style={{ margin: 0 }}>GeoLocation Map</h3>
        </div>

        <span
          style={{
            fontSize: "10px",
            letterSpacing: "1px",
            opacity: 0.55,
          }}
        >
          {points.length} MAPPED IP{points.length === 1 ? "" : "S"}
        </span>
      </div>

      {points.length > 0 ? (
        <div
          style={{
            height: "420px",
            width: "100%",
            overflow: "hidden",
            borderRadius: "10px",
            border: "1px solid rgba(255,255,255,0.08)",
          }}
        >
          <MapContainer
            center={[points[0].latitude, points[0].longitude]}
            zoom={5}
            scrollWheelZoom={true}
            style={{ height: "100%", width: "100%" }}
          >
            <TileLayer
              attribution='&copy; OpenStreetMap contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />

            <MapViewport points={points} />

            {points.map((point, index) => (
              <Marker
                key={`${point.ip || "ip"}-${index}`}
                position={[point.latitude, point.longitude]}
              >
                <Popup>
                  <strong>{point.ip || "Unknown IP"}</strong>
                  <br />
                  {point.city || "Unknown city"}
                  {point.country ? `, ${point.country}` : ""}
                  <br />
                  {point.organization || point.isp || "Organization unavailable"}
                  <br />
                  {point.asn || "ASN unavailable"}
                </Popup>
              </Marker>
            ))}
          </MapContainer>
        </div>
      ) : (
        <div
          style={{
            minHeight: "180px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            textAlign: "center",
            padding: "30px",
            borderRadius: "10px",
            border: "1px dashed rgba(255,255,255,0.10)",
            background: "rgba(255,255,255,0.018)",
          }}
        >
          <div>
            <strong style={{ display: "block", marginBottom: "7px" }}>
              No mappable public IP location available
            </strong>
            <span style={{ fontSize: "12px", opacity: 0.58, lineHeight: 1.5 }}>
              TARVEX26 only places IPs on the map when reliable latitude and longitude
              data are available. Private, reserved, documentation and non-routable
              addresses are intentionally excluded.
            </span>
          </div>
        </div>
      )}
    </section>
  );
}

