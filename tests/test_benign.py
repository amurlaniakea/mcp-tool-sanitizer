import pytest

from mcp_tool_sanitizer.sanitize import find_hidden

# Corpus BENIGNO ADVERSARIAL (AC-7): emoji, CJK, acentos, math unicode, ligaduras.
# NO texto generico. Debe dar 0 findings (no confundir simbolos legítimos con ocultamiento).
BENIGN = [
    "Crear usuario con contraseño seguro 🔒",
    "分析中文文本并执行操作",
    "Listar ficheros del directorio /home",
    "Math: ∀x∈ℝ, x² ≥ 0 — naïve café",
    "Café naïve Über µ Torréfaction",
    "⁅⁆ ⟨⟩ ⟦⟧ ⌊⌋ (delimitadores matemáticos)",
    "ﬁ ﬂ ﬃ (ligaduras legítimas)",
    "① ② ③ (circled digits)",
    "№ § ¶ † ‡ (símbolos tipográficos)",
    "𝐀𝐁𝐂 (Mathematical Bold, distinto de ASCII pero legítimo)",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_no_false_positives(text):
    assert find_hidden(text) == [], f"falso positivo en texto benigno: {text!r}"
