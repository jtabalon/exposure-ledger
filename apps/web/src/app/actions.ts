"use server"

import { revalidatePath } from "next/cache"

import { apiBaseUrl } from "@/lib/assessment-runs"
import {
  dispositionKinds,
  type DispositionActionState,
  type DispositionKind,
  type DispositionTarget,
} from "@/lib/investigations"
import { localDispositionWritesEnabled } from "@/lib/local-dispositions"

const allowedDispositionKinds = new Set<DispositionKind>(dispositionKinds)
const uuidPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const datePattern = /^\d{4}-\d{2}-\d{2}$/

function formString(formData: FormData, name: string): string {
  const value = formData.get(name)
  return typeof value === "string" ? value.trim() : ""
}

export async function recordDisposition(
  target: DispositionTarget | null,
  _previous: DispositionActionState,
  formData: FormData,
): Promise<DispositionActionState> {
  if (!localDispositionWritesEnabled()) {
    return { status: "error", message: "Human Disposition writes are disabled here." }
  }
  const investigationId = target?.investigationId ?? ""
  const investigationRevisionId = target?.investigationRevisionId ?? ""
  const rawKind = formString(formData, "kind")
  const rationale = formString(formData, "rationale")
  const expirationDate = formString(formData, "expirationDate")
  const reviewDate = formString(formData, "reviewDate")
  if (
    !uuidPattern.test(investigationId) ||
    !uuidPattern.test(investigationRevisionId) ||
    !allowedDispositionKinds.has(rawKind as DispositionKind)
  ) {
    return { status: "error", message: "Complete the required Disposition fields." }
  }
  if (
    (expirationDate && !datePattern.test(expirationDate)) ||
    (reviewDate && !datePattern.test(reviewDate))
  ) {
    return { status: "error", message: "Use a valid expiration or review date." }
  }
  if (rawKind === "accept_risk" && (!rationale || (!expirationDate && !reviewDate))) {
    return {
      status: "error",
      message: "Risk acceptance requires a rationale and an expiration or review date.",
    }
  }

  try {
    const response = await fetch(
      `${apiBaseUrl()}/api/v1/investigations/${investigationId}/dispositions`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          investigationRevisionId,
          kind: rawKind,
          rationale: rationale || null,
          expirationDate: expirationDate || null,
          reviewDate: reviewDate || null,
        }),
        signal: AbortSignal.timeout(3000),
      },
    )
    if (!response.ok) {
      return { status: "error", message: `Disposition API returned HTTP ${response.status}.` }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown connection error"
    return { status: "error", message: `Disposition API unavailable: ${message}` }
  }

  revalidatePath("/")
  return { status: "success", message: "Human Disposition recorded as an append-only event." }
}
