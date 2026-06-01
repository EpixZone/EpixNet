import time
import re

from Plugin import PluginManager
from Db.DbQuery import DbQuery
from Debug import Debug
from util import helper
from util.Flag import flag


def sanitize_sql_field(field, fallback="date_added"):
    """Ensure a field name is a safe SQL identifier.

    Accepts simple identifiers (`foo`) and qualified column refs (`tbl.col`).
    Rejects anything else (whitespace, operators, quotes, concatenation, etc.)
    and returns the fallback. The fallback itself must also pass this regex.
    """
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$', field):
        return field
    return fallback


# Tokens that always terminate or comment-out a statement and have no
# legitimate use inside a single-SELECT feed query.
_FORBIDDEN_LITERALS = re.compile(r"(;|--|/\*|\*/)")

# Mutation / admin / multi-statement keywords. These are only dangerous when
# used as SQL statements — many (REPLACE, ABORT, BEGIN, END) are also valid
# in expression / function-call position, so we only flag them when they are
# NOT immediately followed by `(` (function call form).
_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(ATTACH|DETACH|PRAGMA|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|VACUUM"
    r"|REINDEX|ANALYZE|BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b\s*(?!\()",
    re.IGNORECASE,
)


def is_safe_feed_sql(sql):
    """Reject SQL that could break out of a single SELECT statement context.

    Returns True iff the string is safe to embed as a subquery / pass to
    sqlite3.Cursor.execute() without enabling SQL injection or multi-
    statement execution.

    Rejects:
      - statement terminators (`;`) and SQL comments (`--`, `/* */`),
      - mutation/admin/transaction keywords (INSERT, UPDATE, DELETE, DROP,
        ATTACH, PRAGMA, BEGIN, COMMIT, ...) in statement position,
      - NUL bytes.

    Allows function-call uses of keywords that share a name with a function
    (e.g. REPLACE(col, 'x', 'y') is permitted because it's followed by `(`).
    """
    if not isinstance(sql, str) or not sql.strip():
        return False
    if "\x00" in sql:
        return False
    if _FORBIDDEN_LITERALS.search(sql):
        return False
    if _FORBIDDEN_KEYWORDS.search(sql):
        return False
    return True


@PluginManager.registerTo("UiWebsocket")
class UiWebsocketPlugin(object):
    def formatSiteInfo(self, site, create_user=True):
        site_info = super(UiWebsocketPlugin, self).formatSiteInfo(site, create_user=create_user)
        feed_following = self.user.sites.get(site.address, {}).get("follow", None)
        if feed_following == None:
            site_info["feed_follow_num"] = None
        else:
            site_info["feed_follow_num"] = len(feed_following)
        return site_info

    def actionFeedFollow(self, to, feeds):
        self.user.setFeedFollow(self.site.address, feeds)
        self.user.save()
        self.response(to, "ok")

    def actionFeedListFollow(self, to):
        feeds = self.user.sites.get(self.site.address, {}).get("follow", {})
        self.response(to, feeds)

    @flag.admin
    def actionFeedQuery(self, to, limit=10, day_limit=3):
        from Site import SiteManager

        limit = int(limit)
        day_limit = int(day_limit) if day_limit is not None else 0

        rows = []
        stats = []

        total_s = time.time()
        num_sites = 0

        for address, site_data in list(self.user.sites.items()):
            feeds = site_data.get("follow")
            if not feeds:
                continue
            if type(feeds) is not dict:
                self.log.debug("Invalid feed for site %s" % address)
                continue
            num_sites += 1
            for name, query_set in feeds.items():
                site = SiteManager.site_manager.get(address)
                if not site or not site.storage.has_db:
                    continue

                s = time.time()
                try:
                    query_raw, params = query_set
                    if not is_safe_feed_sql(query_raw):
                        self.log.error("%s feed query %s rejected: unsafe SQL" % (address, name))
                        stats.append({"site": site.address, "feed_name": name, "error": "unsafe SQL"})
                        continue
                    query_parts = re.split(r"UNION(?:\s+ALL|)", query_raw)
                    for i, query_part in enumerate(query_parts):
                        db_query = DbQuery(query_part)
                        if day_limit:
                            # day_limit is int()-coerced at the top of the action
                            date_field = sanitize_sql_field(db_query.fields.get("date_added", "date_added"))
                            has_group_by = "GROUP BY" in query_part.upper()
                            if has_group_by:
                                # Aggregate aliases can't go in WHERE; use HAVING
                                having = " HAVING %s > strftime('%%s', 'now', '-%d day')" % (date_field, int(day_limit))
                                query_part = query_part.rstrip() + having
                            else:
                                where = " WHERE %s > strftime('%%s', 'now', '-%d day')" % (date_field, int(day_limit))
                                if "WHERE" in query_part:
                                    query_part = re.sub(r"WHERE (.*?)(?=$| GROUP BY)", where + r" AND (\1)", query_part, flags=re.DOTALL)
                                else:
                                    query_part += where
                        query_parts[i] = query_part
                    query = " UNION ".join(query_parts)

                    if ":params" in query:
                        query_params = map(helper.sqlquote, params)
                        query = query.replace(":params", ",".join(query_params))

                    full_query = query + " ORDER BY date_added DESC LIMIT %d" % int(limit)
                    if not is_safe_feed_sql(full_query):
                        self.log.error("%s feed query %s rejected after rewrite: unsafe SQL" % (address, name))
                        stats.append({"site": site.address, "feed_name": name, "error": "unsafe SQL"})
                        continue
                    res = site.storage.query(full_query)

                except Exception as err:  # Log error
                    self.log.error("%s feed query %s error: %s" % (address, name, Debug.formatException(err)))
                    stats.append({"site": site.address, "feed_name": name, "error": str(err)})
                    continue

                row_count = 0
                for row in res:
                    row = dict(row)
                    if not isinstance(row["date_added"], (int, float, complex)):
                        self.log.debug("Invalid date_added from site %s: %r" % (address, row["date_added"]))
                        continue
                    if row["date_added"] > 1000000000000:  # Formatted as millseconds
                        row["date_added"] = row["date_added"] / 1000
                    if "date_added" not in row or row["date_added"] > time.time() + 120:
                        self.log.debug("Newsfeed item from the future from from site %s" % address)
                        continue  # Feed item is in the future, skip it
                    row["site"] = address
                    row["feed_name"] = name
                    rows.append(row)
                    row_count += 1
                stats.append({"site": site.address, "feed_name": name, "taken": round(time.time() - s, 3)})
                time.sleep(0.001)
        return self.response(to, {"rows": rows, "stats": stats, "num": len(rows), "sites": num_sites, "taken": round(time.time() - total_s, 3)})

    def parseSearch(self, search):
        parts = re.split("(site|type):", search)
        if len(parts) > 1:  # Found filter
            search_text = parts[0]
            parts = [part.strip() for part in parts]
            filters = dict(zip(parts[1::2], parts[2::2]))
        else:
            search_text = search
            filters = {}
        return [search_text, filters]

    def actionFeedSearch(self, to, search, limit=30, day_limit=30):
        if "ADMIN" not in self.site.settings["permissions"]:
            return self.response(to, "FeedSearch not allowed")

        from Site import SiteManager

        limit = int(limit)
        day_limit = int(day_limit) if day_limit is not None else 0

        rows = []
        stats = []
        num_sites = 0
        total_s = time.time()

        search_text, filters = self.parseSearch(search)

        for address, site in SiteManager.site_manager.list().items():
            if not site.storage.has_db:
                continue

            if "site" in filters:
                if filters["site"].lower() not in [site.address, site.content_manager.contents["content.json"].get("title").lower()]:
                    continue

            if site.storage.db:  # Database loaded
                feeds = site.storage.db.schema.get("feeds")
            else:
                try:
                    feeds = site.storage.loadJson("dbschema.json").get("feeds")
                except:
                    continue

            if not feeds:
                continue

            num_sites += 1

            for name, query in feeds.items():
                s = time.time()
                try:
                    # Reject feed queries that contain anything that could
                    # break out of a SELECT subquery context.
                    if not is_safe_feed_sql(query):
                        self.log.error("%s feed query %s rejected: unsafe SQL" % (address, name))
                        stats.append({"site": site.address, "feed_name": name, "error": "unsafe SQL"})
                        continue

                    db_query = DbQuery(query)

                    params = []
                    # Type filter is on the literal SELECT, applied pre-wrap
                    if filters.get("type") and filters["type"] not in query:
                        continue

                    if day_limit:
                        # day_limit is int()-coerced at the top of the action
                        search_date_field = sanitize_sql_field(db_query.fields.get("date_added", "date_added"))
                        db_query.wheres.append(
                            "%s > strftime('%%s', 'now', '-%d day')" % (search_date_field, int(day_limit))
                        )

                    # Search filter is applied on the outer SELECT aliases to avoid
                    # ambiguous-column errors when the inner query joins multiple
                    # tables that share `body`/`title` columns. The outer template
                    # uses bound parameters for the search text and an int-coerced
                    # LIMIT — no user-controlled string is interpolated.
                    if search_text:
                        inner_sql = str(db_query)
                        if not is_safe_feed_sql(inner_sql):
                            self.log.error("%s feed query %s rejected after rewrite: unsafe SQL" % (address, name))
                            stats.append({"site": site.address, "feed_name": name, "error": "unsafe SQL"})
                            continue
                        outer_sql = "SELECT * FROM (\n%s\n) WHERE (body LIKE ? OR title LIKE ?) ORDER BY date_added DESC LIMIT %d" % (
                            inner_sql, int(limit)
                        )
                        search_like = "%" + search_text.replace(" ", "%") + "%"
                        params.append(search_like)
                        params.append(search_like)
                        res = site.storage.query(outer_sql, params)
                    else:
                        db_query.parts["ORDER BY"] = "date_added DESC"
                        db_query.parts["LIMIT"] = "%d" % int(limit)
                        res = site.storage.query(str(db_query), params)
                except Exception as err:
                    self.log.error("%s feed query %s error: %s" % (address, name, Debug.formatException(err)))
                    stats.append({"site": site.address, "feed_name": name, "error": str(err), "query": query})
                    continue
                for row in res:
                    row = dict(row)
                    if not row["date_added"] or row["date_added"] > time.time() + 120:
                        continue  # Feed item is in the future, skip it
                    row["site"] = address
                    row["feed_name"] = name
                    rows.append(row)
                stats.append({"site": site.address, "feed_name": name, "taken": round(time.time() - s, 3)})
        return self.response(to, {"rows": rows, "num": len(rows), "sites": num_sites, "taken": round(time.time() - total_s, 3), "stats": stats})


@PluginManager.registerTo("User")
class UserPlugin(object):
    # Set queries that user follows
    def setFeedFollow(self, address, feeds):
        site_data = self.getSiteData(address)
        site_data["follow"] = feeds
        self.save()
        return site_data
