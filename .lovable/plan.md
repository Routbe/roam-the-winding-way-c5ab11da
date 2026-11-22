# Plan: ROUT live laten draaien op je eigen Neon-database

Neon blijft je database en er komt niets op Lovable Cloud. De code blijft exact zoals in je repo: in dit plan staan geen wijzigingen aan de app.

## Stappen
1. **Eerst de lees-ronde afmaken.** Het overzicht van alle pagina's en de controle van de beveiliging lopen nog. Je krijgt daarna een volledig rapport.
2. **De app laten verbinden met Neon.** Via een veilig formulier in de chat vraag ik:
   - de verbinding voor het app-account (rout_app), niet die van de eigenaar;
   - de geheime sleutel voor het inloggen (BETTER_AUTH_SECRET);
   - de hoofdsleutel van de kluis (ROUT_VAULT_KEK).

   Opslag, betalingen en e-mail (Scaleway, Stripe, Brevo) blijven je eigen diensten. Die sleutels vraag ik pas als je ze wilt testen.
3. **Controleren in de preview.** Ik test het aanmelden met een passkey, of een profiel geladen wordt en of een niet-beheerder het beheergedeelte niet te zien krijgt.
4. **Update 0300 (vertrouwen voor organisaties):** die staat in de code, maar nog niet op Neon. Ik voer hem alleen uit na jouw uitdrukkelijke GO, met het eigen script in je repo dat dat ene bestand uitvoert.

## Technische details
- Bij het uitvoeren schakelt de app zelf over op rout_app en weigert dan een eigenaarsaccount. Gebruik dus niet de verbinding van neondb_owner als DATABASE_URL.
- De koppeling met Neon als eigenaar dient alleen om te lezen en te controleren vanuit de chat.
- De achtergronddienst (de map worker/) heeft een eigen Linux-server nodig en draait niet in deze preview.
