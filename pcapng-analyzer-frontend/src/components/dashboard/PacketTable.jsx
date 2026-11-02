import {
  memo,
  useCallback,
  useMemo,
  useRef,
  useState,
} from "react";

import "./PacketTable.css";

import {
  formatNumber,
} from "../../utils/packetFormat";


/* =========================================================
   CONFIG
   ========================================================= */

const ROW_HEIGHT = 25;

const OVERSCAN_ROWS = 8;


/* =========================================================
   PACKET ROW
   ========================================================= */

const PacketRow = memo(
  function PacketRow({
    packet,
  }) {
    return (
      <tr
        data-packet-number={
          packet.packet_number
        }
      >

        <td data-column="number">
          <span className="packet-number">
            {packet.packet_number}
          </span>
        </td>


        <td data-column="interface">
          <span className="interface-badge">
            IF {packet.interface_id}
          </span>
        </td>


        <td data-column="length">
          {formatNumber(
            packet.captured_length
          )}{" "}
          B
        </td>


        <td data-column="entropy">
          <span className="entropy">
            {Number(
              packet.entropy
            ).toFixed(4)}
          </span>
        </td>


        <td data-column="status">
          <span className="packet-status">
            Normal
          </span>
        </td>

      </tr>
    );
  }
);


/* =========================================================
   PACKET TABLE
   ========================================================= */

const PacketTable = memo(
  function PacketTable({
    packets,
    onSelect,
  }) {
    const scrollRef =
      useRef(null);

    const animationFrameRef =
      useRef(null);


    /*
     * =====================================================
     * VIRTUAL SCROLL STATE
     * =====================================================
     */

    const [
      viewport,
      setViewport,
    ] = useState({
      scrollTop: 0,
      height: 600,
    });


    /*
     * =====================================================
     * CURRENT SELECTION
     *
     * Detta ligger INTE i React state.
     *
     * Vi markerar DOM-elementet direkt.
     * =====================================================
     */

    const selectedRowRef =
      useRef(null);

    const selectedCellRef =
      useRef(null);


    /*
     * =====================================================
     * PACKET MAP
     *
     * packet_number -> packet
     * =====================================================
     */

    const packetMap = useMemo(() => {
      const map = new Map();

      for (const packet of packets) {
        map.set(
          packet.packet_number,
          packet
        );
      }

      return map;
    }, [packets]);


    /*
     * =====================================================
     * UPDATE VIEWPORT
     * =====================================================
     */

    const updateViewport =
      useCallback(() => {
        const element =
          scrollRef.current;

        if (!element) {
          return;
        }

        const next = {
          scrollTop:
            element.scrollTop,

          height:
            element.clientHeight,
        };


        setViewport(
          (previous) => {
            if (
              previous.scrollTop ===
                next.scrollTop &&
              previous.height ===
                next.height
            ) {
              return previous;
            }

            return next;
          }
        );
      }, []);


    /*
     * =====================================================
     * SCROLL HANDLER
     *
     * requestAnimationFrame gör att vi inte försöker
     * rendera om React för varje pixel scroll.
     * =====================================================
     */

    const handleScroll =
      useCallback(() => {
        if (
          animationFrameRef.current !==
          null
        ) {
          return;
        }


        animationFrameRef.current =
          requestAnimationFrame(() => {
            animationFrameRef.current =
              null;

            updateViewport();
          });
      }, [
        updateViewport,
      ]);


    /*
     * =====================================================
     * INITIAL VIEWPORT
     * =====================================================
     */

    const handleViewportRef =
      useCallback(
        (element) => {
          scrollRef.current =
            element;

          if (!element) {
            return;
          }


          setViewport({
            scrollTop:
              element.scrollTop,

            height:
              element.clientHeight,
          });
        },
        []
      );


    /*
     * =====================================================
     * CALCULATE VISIBLE RANGE
     * =====================================================
     */

    const visibleRange =
      useMemo(() => {
        const total =
          packets.length;


        if (total === 0) {
          return {
            start: 0,
            end: 0,
          };
        }


        const rawStart =
          Math.floor(
            viewport.scrollTop /
              ROW_HEIGHT
          );


        const rawEnd =
          Math.ceil(
            (
              viewport.scrollTop +
              viewport.height
            ) /
              ROW_HEIGHT
          );


        const start =
          Math.max(
            0,
            rawStart -
              OVERSCAN_ROWS
          );


        const end =
          Math.min(
            total,
            rawEnd +
              OVERSCAN_ROWS
          );


        return {
          start,
          end,
        };
      }, [
        packets.length,
        viewport.scrollTop,
        viewport.height,
      ]);


    /*
     * =====================================================
     * ONLY THESE PACKETS ARE RENDERED
     * =====================================================
     */

    const visiblePackets =
      useMemo(() => {
        return packets.slice(
          visibleRange.start,
          visibleRange.end
        );
      }, [
        packets,
        visibleRange.start,
        visibleRange.end,
      ]);


    /*
     * =====================================================
     * SPACER HEIGHTS
     * =====================================================
     */

    const topHeight =
      visibleRange.start *
      ROW_HEIGHT;


    const bottomHeight =
      (
        packets.length -
        visibleRange.end
      ) *
      ROW_HEIGHT;


    /*
     * =====================================================
     * CELL CLICK
     *
     * Event delegation:
     *
     * EN ENDA click-handler för hela tbody.
     * =====================================================
     */

    const handleTableClick =
      useCallback(
        (event) => {
          const cell =
            event.target.closest(
              "td[data-column]"
            );

          if (!cell) {
            return;
          }


          const row =
            cell.closest(
              "tr[data-packet-number]"
            );

          if (!row) {
            return;
          }


          const packetNumber =
            Number(
              row.dataset.packetNumber
            );


          if (
            !Number.isFinite(
              packetNumber
            )
          ) {
            return;
          }


          /*
           * Hämta packet O(1).
           */

          const packet =
            packetMap.get(
              packetNumber
            );


          if (!packet) {
            return;
          }


          /*
           * Ta bort tidigare selection.
           */

          if (
            selectedRowRef.current &&
            selectedRowRef.current !==
              row
          ) {
            selectedRowRef.current.classList.remove(
              "packet-selected"
            );
          }


          if (
            selectedCellRef.current &&
            selectedCellRef.current !==
              cell
          ) {
            selectedCellRef.current.classList.remove(
              "cell-selected"
            );
          }


          /*
           * Markera packet.
           */

          row.classList.add(
            "packet-selected"
          );


          /*
           * Markera exakt cell.
           */

          cell.classList.add(
            "cell-selected"
          );


          /*
           * Spara DOM references.
           */

          selectedRowRef.current =
            row;

          selectedCellRef.current =
            cell;


          /*
           * Endast inspector behöver React-update.
           */

          onSelect(packet);
        },
        [
          packetMap,
          onSelect,
        ]
      );


    /*
     * =====================================================
     * RENDER
     * =====================================================
     */

    return (
      <div className="table-wrapper">

        <div
          ref={handleViewportRef}
          className="table-scroll"
          onScroll={handleScroll}
        >

          <table className="packet-table">

            <thead>
              <tr>

                <th>
                  #
                </th>

                <th>
                  Interface
                </th>

                <th>
                  Length
                </th>

                <th>
                  Entropy
                </th>

                <th>
                  Status
                </th>

              </tr>
            </thead>


            <tbody
              onClick={
                handleTableClick
              }
            >

              {/* =========================================
                  TOP SPACER

                  Representerar alla paket ovanför
                  viewporten utan att rendera dem.
                  ========================================= */}

              {topHeight > 0 && (
                <tr
                  className="virtual-spacer"
                  aria-hidden="true"
                >
                  <td
                    colSpan="5"
                    style={{
                      height: topHeight,
                    }}
                  />
                </tr>
              )}


              {/* =========================================
                  ACTUAL VISIBLE PACKETS
                  ========================================= */}

              {visiblePackets.map(
                (packet) => (
                  <PacketRow
                    key={
                      packet.packet_number
                    }
                    packet={packet}
                  />
                )
              )}


              {/* =========================================
                  BOTTOM SPACER

                  Representerar alla paket under
                  viewporten utan att rendera dem.
                  ========================================= */}

              {bottomHeight > 0 && (
                <tr
                  className="virtual-spacer"
                  aria-hidden="true"
                >
                  <td
                    colSpan="5"
                    style={{
                      height:
                        bottomHeight,
                    }}
                  />
                </tr>
              )}

            </tbody>

          </table>

        </div>

      </div>
    );
  }
);


export default PacketTable;