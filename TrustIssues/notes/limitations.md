Limitation connue : FBR résiduel de 1.1% sur enterprise_poisoned_invoice (email_draft).
Cause : chevauchement textuel coïncidentiel entre un brouillon légitime et le document 
non fiable source, faussement détecté par instruction_in_untrusted().
Piste d'amélioration future : détection ciblée sur les valeurs sensibles précises 
(tokens, identifiants) plutôt que chevauchement textuel général.