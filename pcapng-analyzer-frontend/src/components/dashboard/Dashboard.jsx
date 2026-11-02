
import {
  useCallback,
  useState,
} from "react";

import "./Dashboard.css";

import {
  ShieldIcon,
  FileIcon,
} from "../icons/icons";

import DataCard from "./DataCard";
import PacketTable from "./PacketTable";
import PacketInspector from "../inspector/PacketInspector";

import {
  formatNumber,
} from "../../utils/packetFormat";


export default function Dashboard({
  overview,
  packets,
  filename,
  onReset,
}) {
  const [
    selectedPacket,
    setSelectedPacket,
  ] = useState(null);


  const packetCount =
    overview?.packets ??
    packets.length;


  /*
   * Stable callback.
   *
   * Den här funktionen skapas bara en gång
   * istället för varje render.
   */
  const handleCloseInspector =
    useCallback(() => {
      setSelectedPacket(null);
    }, []);


  return (
    <div className="dashboard-page">

      {/* ======================================================
          TOP BAR
          ====================================================== */}

      <header className="topbar">

        <div className="topbar-left">

          <div className="mini-logo">
            <ShieldIcon />
          </div>

          <div>
            <div className="topbar-title">
              PCAPNG Analyzer
            </div>

            <div className="topbar-file">
              <FileIcon />
              {filename || "Capture"}
            </div>
          </div>

        </div>


        <button
          className="reset-button"
          onClick={onReset}
        >
          ← New capture
        </button>

      </header>


      {/* ======================================================
          ANALYSIS WORKSPACE
          ====================================================== */}

      <main className="packet-analysis">

        {/* ====================================================
            PACKET LIST
            ==================================================== */}

        <section className="packet-list-panel">

          <DataCard
            title="Packet List"
            right={
              <span className="table-info">
                {selectedPacket
                  ? `Packet #${selectedPacket.packet_number}`
                  : `${formatNumber(packetCount)} packets`}
              </span>
            }
          >

            <PacketTable
              packets={packets}
              selectedPacket={selectedPacket}
              onSelect={setSelectedPacket}
            />

          </DataCard>

        </section>


        {/* ====================================================
            PACKET INFORMATION
            ==================================================== */}

        <section className="packet-information-panel">

          <PacketInspector
            packet={selectedPacket}
            onClose={handleCloseInspector}
          />

        </section>

      </main>

    </div>
  );
}

