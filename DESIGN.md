<!-- SEED: re-run /impeccable document once there's code to capture the actual tokens and components. -->

---
name: MCPShield
description: Security scanner for MCP server configurations. Sharp, technical, trustworthy.
---

# Design System: MCPShield

## 1. Overview

**Creative North Star: "The Audit Ledger"**

The page reads like a formal security audit rendered as a living document. Every surface is typeset in monospace. The palette is nearly monochrome: warm paper neutrals with a single accent reserved for the moments that matter most. There is no decoration. Information is the design.

The atmosphere is clinical precision: the confidence of a well-structured incident report, not the anxiety of a threat dashboard. Density is high. Whitespace is earned, not generous. The eye should move through structured data the way it moves through a well-formatted terminal output: fast, confident, never lost.

Motion is the counterweight to the visual restraint. Sections enter with choreographed precision, staggered reveals that feel like lines of an audit report printing in sequence. Scroll-linked transitions mark progress through the page. The stillness of the typography is offset by the deliberateness of the movement. Nothing decorative; everything structural.

This system explicitly rejects: navy backgrounds with blue gradients, shield icons, stock photography of locked padlocks, purple gradients with floating particles, "powered by AI" badges, hand-drawn illustrations, rounded everything, emoji-heavy UI, mascot characters, the hero-metric template, identical card grids.

**Key Characteristics:**
- Monospace throughout. Not as an accent. As the voice.
- Restrained to the point of severity. One accent color, used on less than 10% of any surface.
- High information density. Low decorative noise.
- Choreographed motion that compensates for visual austerity.
- Light, paper-like base that evokes printed documentation, not dark terminal aesthetics.

## 2. Colors

**The Restraint Rule.** One accent color. Less than 10% of any given surface. Its rarity is the point. When it appears, it signals importance: a severity rating, a call to action, a critical finding.

### Strategy

Restrained: tinted neutrals carry 90%+ of the surface. The neutrals are warm, not cool: paper, parchment, warm gray. They should feel like the background of a printed technical manual, not a sterile white application frame.

### Primary
- **[Accent]** `[to be resolved during implementation]`: Used exclusively for severity indicators, primary calls to action, and single-word emphasis. The hue should feel urgent without being alarming. Avoid red (alarmist), blue (corporate), green (terminal cliché). Candidates: amber, warm vermillion, deep gold.

### Neutral
- **[Paper base]** `[to be resolved during implementation]`: Warm light background. Not white. Should read like aged printer paper or thermal receipt stock: slightly warm, slightly textured in perception.
- **[Ink]** `[to be resolved during implementation]`: Near-black for body text. Warm, not cool. Should feel like printer ink on paper, not pixel-black on screen.
- **[Rule]** `[to be resolved during implementation]`: Mid-tone neutral for borders, dividers, horizontal rules. Visible but quiet.
- **[Muted]** `[to be resolved during implementation]`: Light neutral for secondary text, metadata, timestamps. Present but receded.

### Named Rules
**The Paper Rule.** Every neutral is tinted warm. No cool grays, no pure whites, no blue undertones. The surface should feel like it has material weight, not like it floats.

## 3. Typography

**Mono Font:** `[font to be chosen at implementation]`
**Considerations:** JetBrains Mono, IBM Plex Mono, Berkeley Mono, or Violet Sans for a less common choice. The font must have a clear weight range (300-700) and read well at body size (14-16px). A slab-serif mono (like Courier) could work for display; a geometric mono for body. Consider pairing two monos if one has more personality at display scale.

**Character:** The monospace typeface is the voice of the brand. It speaks in fixed-width columns, aligned data, and predictable rhythm. It is not decorative mono. It is structural mono. Every line break is intentional. Every alignment is precise.

### Hierarchy
- **Display** (weight 700, clamp for responsive, line-height 1): Hero statements only. The tool name, the one-line verdict. Set large enough to stop scrolling.
- **Headline** (weight 600, 1.5-2rem, line-height 1.15): Section heads. Feature names. The structural anchors of the page.
- **Title** (weight 500, 1.125-1.25rem, line-height 1.3): Subsection heads. Finding summaries. The entry points into detail.
- **Body** (weight 400, 0.875-1rem, line-height 1.6): All prose. Cap at 65-75ch. This is the workhorse.
- **Label** (weight 500, 0.75rem, letter-spacing 0.05em, uppercase): Tags, severity badges, metadata keys. The filing system of the page.

### Named Rules
**The Fixed-Width Doctrine.** Every text element uses a monospace font. No sans-serif for body. No serif for display. The monospace is the brand. Deviation breaks trust.

## 4. Elevation

Flat by default. The Audit Ledger does not float. Surfaces sit flush against the paper base, distinguished by tonal shifts (warmer or cooler neutral) and crisp 1px rules, not by shadow. Depth is conveyed through hierarchy and spacing, not through lift.

When elevation is needed for overlays (tooltips, dropdowns, modals), use a single low shadow: tight, warm, barely visible. If it looks like it could belong in a 2014 Material Design spec, it is too heavy.

## 5. Components

`[Components will be documented during implementation, once real UI code exists.]`

## 6. Do's and Don'ts

### Do:
- **Do** use monospace for every text element. Display, body, label, navigation. The fixed-width rhythm is the brand identity.
- **Do** keep the accent color to less than 10% of any surface. Count pixels if you have to.
- **Do** use warm, paper-like neutrals. The surface should feel like a printed document, not a screen.
- **Do** use choreographed motion to create rhythm. Staggered entrances, scroll-linked transitions, sequential reveals. The motion compensates for the visual restraint.
- **Do** use 1px rules and tonal shifts for structure, not shadows or borders.
- **Do** make severity indicators distinguishable by shape and label, not just color. A red circle, an amber triangle, a green check: each must work without its hue.

### Don't:
- **Don't** use navy backgrounds, blue gradients, or shield icons. This is not corporate security marketing. (From PRODUCT.md: "Corporate security aesthetic")
- **Don't** use purple gradients, floating particles, "powered by AI" badges, or abstract neural network illustrations. AI is a tool this product uses, not a visual identity. (From PRODUCT.md: "AI startup landing page")
- **Don't** use hand-drawn illustrations, rounded corners everywhere, confetti, emoji-heavy UI, or mascot characters. Security is serious and the interface reflects that gravity. (From PRODUCT.md: "Playful dev tools")
- **Don't** use border-left or border-right greater than 1px as a colored accent stripe. (Shared design law)
- **Don't** use gradient text. A single solid color for emphasis, weight or size for hierarchy. (Shared design law)
- **Don't** use the hero-metric template: big number, small label, supporting stats, gradient accent. This is a SaaS cliché, not an audit report. (Shared design law)
- **Don't** create identical card grids with the same icon-heading-text pattern repeated. If information needs a card structure, vary the treatment. (Shared design law)
- **Don't** use a sans-serif or serif font for any text element. Monospace only. Deviation from this breaks the brand.
- **Don't** use cool grays or pure whites (`#fff`) for backgrounds. Every neutral is warm-tinted.
- **Don't** add shadows to resting elements. Flat against the paper base. Elevation only for overlays.
