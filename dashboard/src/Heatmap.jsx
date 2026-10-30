import { useEffect, useRef } from 'react'
import * as d3 from 'd3'

export default function Heatmap({ stats, selected, onSelect }) {
  const ref = useRef()

  useEffect(() => {
    const svg = d3.select(ref.current)
    svg.selectAll('*').remove()          // clear the old drawing before redrawing
    if (!stats.length) return

    const cell = 100, gap = 8, perRow = 8
    const max = d3.max(stats, d => +d.count)
    // colour scale: 0 alerts = pale yellow, max alerts = dark red
    const color = d3.scaleSequential(d3.interpolateYlOrRd).domain([0, max])

    const g = svg.selectAll('g').data(stats).enter().append('g')
      .attr('transform', (d, i) =>
        `translate(${(i % perRow) * (cell + gap)}, ${Math.floor(i / perRow) * (cell + gap)})`)
      .style('cursor', 'pointer')
      .on('click', (e, d) => onSelect(selected === d.technique_id ? null : d.technique_id))

    g.append('rect').attr('width', cell).attr('height', cell).attr('rx', 6)
      .attr('fill', d => color(+d.count))
      .attr('stroke', d => (d.technique_id === selected ? '#ffffff' : 'none'))
      .attr('stroke-width', 3)

    g.append('text').attr('x', cell / 2).attr('y', cell / 2 - 4).attr('text-anchor', 'middle')
      .attr('fill', '#111').attr('font-weight', 'bold').text(d => d.technique_id)
    g.append('text').attr('x', cell / 2).attr('y', cell / 2 + 16).attr('text-anchor', 'middle')
      .attr('fill', '#111').attr('font-size', 12).text(d => `${d.count} alert(s)`)

    svg.attr('height', Math.ceil(stats.length / perRow) * (cell + gap))
  }, [stats, selected])

  return <svg ref={ref} width="100%" height="110" />
}
