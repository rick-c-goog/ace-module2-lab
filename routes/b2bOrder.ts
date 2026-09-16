/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const DANGEROUS_PATTERNS = [
  /(?:constructor|__proto__|prototype)/i,
  /\b(?:process|mainModule|child_process|execSync|spawnSync|exec|spawn)\b/i,
  /\b(?:fromCharCode|fromCodePoint)\b/i,
  /\bFunction\b/,
  /\b(?:eval|require|import)\b/i,
  /\b(?:getPrototypeOf|setPrototypeOf|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__)\b/i,
  /\b(?:global|globalThis)\b/i
]

function hasSandboxBreakout (data: unknown): boolean {
  if (!data) return false
  const str = typeof data === 'string' ? data : JSON.stringify(data)
  const unescaped = str
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))

  const deconcatenated = unescaped
    .replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '')
    .replace(/['"`]\s*\+\s*['"`]/g, '')

  return DANGEROUS_PATTERNS.some(pattern => pattern.test(str) || pattern.test(unescaped) || pattern.test(deconcatenated))
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      try {
        if (hasSandboxBreakout(orderLinesData)) {
          throw new Error('Sandbox breakout attempt detected')
        }
        const safeEvalWrapper = (code: string) => {
          if (hasSandboxBreakout(code)) {
            throw new Error('Sandbox breakout attempt detected')
          }
          return safeEval(code)
        }
        const sandbox = { safeEval: safeEvalWrapper, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
