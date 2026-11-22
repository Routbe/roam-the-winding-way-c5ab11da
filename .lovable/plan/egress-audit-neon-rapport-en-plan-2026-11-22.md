# Egress-audit Neon: rapport en plan

## Kort rapport

**Wat de database laat zien (gemeten, alleen gelezen):**
- De database zelf is klein (34 MB) en de foto-tabel `avatar_objects` is maar 4,9 MB. Er zijn geen grote PDF's of afbeeldingen die bij elke query meegaan. Oorzaak 1 is dus niet de hoofdbron.
- Sinds de start zijn er wel **1,2 miljoen transacties** geweest, bij 22 gebruikers. Het verkeer komt dus van **heel veel kleine, herhaalde verzoeken**, niet van grote rijen.
- De tabellen `users` (51.773 volledige scans), `profiles` (39.582) en `neon_auth.session` (35.174) worden bij bijna elk verzoek opnieuw gelezen.
- Bij de verbindingen zag ik een programma dat de volledige tabelstructuur ophaalt (kolomnamen, verplicht of niet, standaardwaarden). Dat patroon zit in de sign-in-bibliotheek. Hoe vaak het draait, is **nog niet bevestigd**.

**Top 3 grootste verbruikers in de code:**
1. **Pagina's die automatisch blijven verversen terwijl ze open staan (oorzaak 2).** De status onderaan elke pagina vraagt elke 60 s de database (`StatusWidget.tsx:23-40`). Het "nu aan het luisteren"-blokje op een profiel doet dat elke 20 tot 30 s, ook als het antwoord nog vers in de database staat (`NowPlaying.tsx:21-34, 207-216`, `spotify-presence.server.ts:165-186`). De aanmeldlogs in de console verversen zelfs elke 3 s. Daarnaast vraagt de worker elke 30 s naar nieuwe taken, ook als er geen zijn. Elk open tabblad of preview vermenigvuldigt dit.
2. **Publieke profielen worden dubbel en zonder cache geladen (oorzaak 3).** `/$username` haalt het profiel op de server op, en daarna nog eens in de browser via `useProfileRecord`, zonder het eerste resultaat te gebruiken. Per bezoek zijn dat zo'n 12 queries. Telkens gaan ook `blocks` en `display_prefs` mee, en er staan geen `Cache-Control`- of stale-while-revalidate-headers op. `/api/badge/key` gebruikt de database niet en heeft al een uur cache.
3. **Previews en ontwikkeling tegen productie (oorzaak 5).** Er is geen tweede database voor tests of previews. Ook deze Lovable-preview gebruikt nu je productie-`DATABASE_URL`, en de overdracht vermeldt dat oudere previews dat ook al deden. Elke open preview draait dan dezelfde automatische verversing mee. De Vitest-tests die ik bekeek, vervangen de database door een nep-versie. Er is echter geen algemene blokkade die echte verbindingen tijdens tests verhindert.

**Kleiner, maar wel echt:**
- **Tellingen in het beheer (oorzaak 4).** Het beheer haalt voor tellingen alle scans en alle badges op en telt daarna in de app (`admin-ops.server.ts:42-52, 155-174`). Zoeken op e-mail haalt 1000 gebruikers op met `select *`.
- **Foto's en documenten (oorzaak 1).** De reservefoto's in Neon (`avatar_objects`) en de ondertekeningsdocumenten (`openSignRequest` stuurt beide PDF's mee) kunnen later groot worden. Vandaag zijn ze klein.

## Veilig plan (volgorde = eerst meten, dan het meeste effect, nooit risico voor live)

1. **Eerst meten, zonder iets te veranderen.** In de Neon-console bekijk je onder Monitoring hoe het verkeer per uur verloopt, en vergelijkt dat met wanneer previews open stonden. Op jouw GO zet ik de meetmodule `pg_stat_statements` aan. Dat voegt alleen tellers toe en verandert geen data. Daarmee zien we per query hoeveel rijen en hoe vaak hij draait, en kunnen we vaststellen of het ophalen van de tabelstructuur echt een grote verbruiker is.
2. **Previews loskoppelen van productie.** Je maakt in Neon een aparte kopie (branch) "preview", en die wordt de `DATABASE_URL` van deze Lovable-preview. Productie blijft onaangeroerd. In de testopzet komt een blokkade die stopt zodra een test een echte database probeert te gebruiken.
3. **Het automatisch verversen temperen.**
   - De status onderaan krijgt een korte cache van 60 s op de server en ververst niet meer als het tabblad verborgen is.
   - Het "nu aan het luisteren"-blokje gebruikt eerst een cache in het geheugen en pas daarna de database. Het pauzeert ook als het tabblad niet zichtbaar is.
   - De aanmeldlogs verversen elke 15 s in plaats van elke 3 s.
   - De worker kijkt minder vaak naar nieuwe taken als er geen zijn. Hij reageert al direct op een seintje bij een nieuwe taak, dus vaak vragen is niet nodig.
4. **Publieke profielen zuiniger laden.**
   - De browser hergebruikt het profiel dat de server al ophaalde, in plaats van het opnieuw te vragen.
   - Publieke profielpagina's krijgen `Cache-Control: public, s-maxage=60, stale-while-revalidate=300`. Pagina's van ingelogde gebruikers krijgen nooit gedeelde cache.
5. **Tellingen in het beheer in de database zelf doen** (`count(*) ... group by`), met alleen de nodige kolommen. Zoeken op e-mail gebeurt dan in de database, met een `LIMIT`.
6. **Later, alleen als stap 1 het aantoont:** de reservefoto's verhuizen naar Scaleway, en ondertekeningsdocumenten worden pas opgehaald als je echt op downloaden klikt.

Elke stap is los te doen en terug te draaien. Na elke stap vergelijk ik het verkeer in Neon over 24 uur met de dag ervoor. Migraties komen er niet aan te pas, behalve stap 1 (de meetmodule, alleen na jouw GO).

## Technische details
- Gemeten via pg_stat_user_tables en pg_stat_database: deze tellers zijn nooit gereset (`stats_reset` is leeg). Er waren 3 open verbindingen: `rout_app` via postgres.js, de beheerdienst van Neon Auth en een vraag naar de structuur van de tabellen.
- De herkomst van de structuur-vraag (`attname/attnotnull/atthasdef`) komt overeen met de manier waarop Better Auth de database inleest. Of en hoe vaak die per koude start draait, is pas na stap 1 te bevestigen.
- Neon telt als network transfer wat de database naar de app stuurt. Het lezen van rijen binnen de database telt niet mee. Het grote aantal herhaalde verzoeken zelf kost dus het meeste.
