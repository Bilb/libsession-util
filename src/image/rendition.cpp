#include "session/image/rendition.hpp"

#include <algorithm>

#include "session/image/probe.hpp"
#include "session/image/thumbnail.hpp"
#include "source_internal.hpp"
#include "thumbnail_internal.hpp"

namespace session::image {

std::optional<std::vector<std::byte>> rendition(Source& source, uint32_t edge) {
    auto info = probe(source);
    if (!info || !detail::acceptable(*info))
        return std::nullopt;

    edge = std::clamp(edge, min_rendition_edge, max_rendition_edge);
    uint32_t box = std::min(edge, std::max(info->width, info->height));

    try {
        return detail::finish(
                detail::scaled(source, *info, box, box, false),
                detail::Backdrop::checkerboard,
                thumbnail_quality);
    } catch (...) {
        detail::source_access::rethrow_error(source);
        throw;
    }
}

}  // namespace session::image
