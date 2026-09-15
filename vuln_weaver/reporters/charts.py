"""弱點等級分佈圖，供 python-docx 與 docxtpl 兩種報告器共用。"""
import tempfile
from typing import Dict, Optional

import matplotlib
matplotlib.use("Agg")  # Headless backend
import matplotlib.pyplot as plt  # noqa: E402


def generate_severity_chart(stats: Dict[str, int]) -> Optional[str]:
    """Generate a donut pie chart image and return its temp filepath."""
    # Configure CJK font support for Windows and Linux
    plt.rcParams["font.sans-serif"] = [
        "Microsoft JhengHei",
        "SimHei",
        "PingFang TC",
        "Noto Sans CJK TC",
        "DejaVu Sans",
    ]
    plt.rcParams["axes.unicode_minus"] = False

    labels = []
    sizes = []
    colors = []
    color_map = {
        "Critical": "#D9534F",
        "High": "#ED6C02",
        "Medium": "#F0AD4E",
        "Low": "#0288D1",
        "Info": "#757575",
    }
    zh_labels = {
        "Critical": "極高 (Critical)",
        "High": "高 (High)",
        "Medium": "中 (Medium)",
        "Low": "低 (Low)",
        "Info": "資訊 (Info)",
    }

    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        val = stats.get(sev, 0)
        if val > 0:
            labels.append(f"{zh_labels[sev]}: {val}")
            sizes.append(val)
            colors.append(color_map[sev])

    if not sizes:
        return None

    fig, ax = plt.subplots(figsize=(6, 3.5), subplot_kw=dict(aspect="equal"))
    wedges, texts, autotexts = ax.pie(
        sizes,
        autopct="%1.1f%%",
        pctdistance=0.75,
        colors=colors,
        startangle=140,
        textprops=dict(color="black", fontsize=9),
    )

    # Draw inner circle for donut look
    centre_circle = plt.Circle((0, 0), 0.50, fc="white")
    fig.gca().add_artist(centre_circle)

    # Add legend
    ax.legend(
        wedges,
        labels,
        title="弱點等級分佈",
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1),
        prop={"family": "sans-serif", "size": 9},
    )

    plt.tight_layout()

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = tmp.name
        plt.savefig(tmp_path, dpi=180, bbox_inches="tight")
        plt.close(fig)
        return tmp_path
