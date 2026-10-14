/** Camera limits are visual, not estimates of geolocation accuracy. */
export const HOP_CLEARANCE_PX = 48;
export const MAX_ROUTE_ZOOM = 4;

/** Wait until a meaningful portion of the globe can actually be seen. */
export function globeInViewport(rect: { top: number; bottom: number; left: number; right: number; width: number; height: number }, viewportWidth: number, viewportHeight: number): boolean {
  if (rect.width <= 0 || rect.height <= 0 || viewportWidth <= 0 || viewportHeight <= 0) return false;
  const visibleWidth = Math.max(0, Math.min(rect.right, viewportWidth) - Math.max(rect.left, 0));
  const visibleHeight = Math.max(0, Math.min(rect.bottom, viewportHeight) - Math.max(rect.top, 0));
  return visibleWidth >= Math.min(rect.width, viewportWidth) * .35
    && visibleHeight >= Math.min(rect.height, viewportHeight) * .35;
}

export function focusZoom(distances: number[], radius: number): number {
  const nearby = distances.filter((angle) => angle < Math.PI / 2);
  if (!nearby.length || radius <= 0) return 1;
  const gap = radius * Math.sin(Math.min(...nearby));
  return Math.max(1, Math.min(MAX_ROUTE_ZOOM, HOP_CLEARANCE_PX / Math.max(1, gap)));
}

export function travelDuration(angle: number): number {
  return angle < 1e-6 ? 0 : Math.min(4500, 700 + angle * 2200);
}

export function maintainedRouteZoom(current: number, focus: number): number {
  return Math.max(1, Math.min(MAX_ROUTE_ZOOM, Math.max(current, focus)));
}

export function smoothZoom(current: number, target: number, delta: number): number {
  // Interpolate scale ratios so zooming out feels as gradual as zooming in.
  const blend = 1 - Math.exp(-Math.max(0, delta) / 550);
  return Math.exp(Math.log(current) + (Math.log(target) - Math.log(current)) * blend);
}

export function routeFrame(elapsed: number, travelTimes: number[], dwell = 2400) {
  let start = 0;
  for (let index = 0; index < travelTimes.length; index += 1) {
    const end = start + dwell + travelTimes[index];
    if (elapsed < end || index === travelTimes.length - 1) {
      const progress = travelTimes[index] ? Math.max(0, Math.min(1, (elapsed - start - dwell) / travelTimes[index])) : 0;
      return { index, progress, dwelling: elapsed - start < dwell, finished: elapsed >= end };
    }
    start = end;
  }
  return { index: 0, progress: 0, dwelling: true, finished: true };
}

export function nearestMarker(points: Array<[number, number] | null>, x: number, y: number, reach = 20): number {
  let selected = -1, best = reach;
  points.forEach((point, index) => {
    if (!point) return;
    const distance = Math.hypot(point[0] - x, point[1] - y);
    if (distance < best) { best = distance; selected = index; }
  });
  return selected;
}
