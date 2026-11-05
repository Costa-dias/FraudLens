const MULTI_LABEL_SUFFIXES = new Set([
  "com.br", "org.br", "net.br", "gov.br", "edu.br", "mil.br",
  "co.uk", "org.uk", "ac.uk", "gov.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "govt.nz",
  "com.mx", "com.ar", "com.co", "com.pe", "com.tr", "com.sg", "com.my",
  "co.jp", "co.in", "co.za",
]);

export interface DomainEvidence {
  hostname: string;
  baseDomain: string;
  subdomains: string[];
  path: string;
  hasQuery: boolean;
  brandNote: string | null;
}

function normalizeBrand(value: string): string {
  return value.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function explainDomain(target: string, claimedBrand = ""): DomainEvidence | null {
  try {
    const parsed = new URL(target);
    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const labels = hostname.split(".").filter(Boolean);
    if (labels.length === 0) return null;

    const suffix2 = labels.slice(-2).join(".");
    const suffixLength = MULTI_LABEL_SUFFIXES.has(suffix2) ? 2 : 1;
    const baseLength = Math.min(labels.length, suffixLength + 1);
    const baseDomain = labels.slice(-baseLength).join(".");
    const subdomains = labels.slice(0, -baseLength);
    const brand = normalizeBrand(claimedBrand.trim());
    const baseLabel = normalizeBrand(labels[labels.length - baseLength] ?? "");
    const subdomainMatch = subdomains.some(label => normalizeBrand(label).includes(brand));

    let brandNote: string | null = null;
    if (brand.length >= 2 && !baseLabel.includes(brand) && subdomainMatch) {
      brandNote = `“${claimedBrand.trim()}” aparece em um subdomínio, mas não no domínio base ${baseDomain}. Isso pode confundir a leitura do endereço; confirme o domínio oficial da empresa.`;
    } else if (brand.length >= 2 && baseLabel.includes(brand)) {
      brandNote = `“${claimedBrand.trim()}” aparece no domínio base ${baseDomain}. Isso, por si só, não confirma que o site pertence à marca.`;
    } else if (brand.length >= 2) {
      brandNote = `O nome informado (“${claimedBrand.trim()}”) não aparece no domínio base ${baseDomain}. A marca pode usar outro domínio oficial; confira por um canal conhecido.`;
    }

    return {
      hostname,
      baseDomain,
      subdomains,
      path: parsed.pathname || "/",
      hasQuery: parsed.search.length > 0,
      brandNote,
    };
  } catch {
    return null;
  }
}
