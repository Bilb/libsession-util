#include "session/image/rendition.hpp"

#include <algorithm>

#include "session/image/probe.hpp"
#include "session/image/thumbnail.hpp"
#include "source_internal.hpp"
#include "thumbnail_internal.hpp"

namespace session::image {

bool rendition_is_original(const Info& info, uint32_t edge) {
    edge = std::clamp(edge, min_rendition_edge, max_rendition_edge);
    return (info.format == Format::jpeg || info.format == Format::webp) && info.decodable &&
           info.orientation <= 1 && info.bits_per_sample <= 8 &&
           std::max(info.width, info.height) <= edge;
}

std::optional<std::vector<std::byte>> rendition(Source& source, uint32_t edge) {
    auto info = probe(source);
    if (!info || !detail::acceptable(*info) || !info->within_pixel_limits(true))
        return std::nullopt;

    edge = std::clamp(edge, min_rendition_edge, max_rendition_edge);
    uint32_t box = std::min(edge, std::max(info->width, info->height));

    try {
        return detail::reencode(source, *info, box, thumbnail_quality).bytes;
    } catch (...) {
        detail::source_access::rethrow_error(source);
        throw;
    }
}

}  // namespace session::image
