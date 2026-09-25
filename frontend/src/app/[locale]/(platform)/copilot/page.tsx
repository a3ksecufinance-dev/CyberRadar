'use client'
import { useTranslations } from 'next-intl'
import { useState, useRef, useEffect } from 'react'
import { Send, Bot, User, Sparkles, Loader2 } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api, ApiError } from '@/lib/api'
import { useApiToken } from '@/hooks'
import type { CopilotMessage } from '@/types'

type Message = {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

const suggestions = ['suggestion1', 'suggestion2', 'suggestion3', 'suggestion4'] as const

function TypingIndicator() {
  return (
    <div className="flex items-center gap-1.5 px-1 py-2">
      {[0, 1, 2].map((i) => (
        <span key={i} className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
      ))}
    </div>
  )
}

function renderContent(content: string) {
  // Minimal markdown: bold **text** and line breaks
  return content.split('\n').map((line, i) => {
    const parts = line.split(/(\*\*[^*]+\*\*)/)
    return (
      <p key={i} className={i > 0 ? 'mt-1' : ''}>
        {parts.map((part, j) =>
          part.startsWith('**') ? (
            <strong key={j} className="font-semibold text-slate-100">{part.slice(2, -2)}</strong>
          ) : part
        )}
      </p>
    )
  })
}

export default function CopilotPage() {
  const t = useTranslations('copilot')
  const token = useApiToken()

  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: "Hello! I'm your CyberRadar AI Copilot. I have full visibility into your security posture across all 26 domains. How can I help you today?",
      timestamp: new Date(),
    },
  ])
  const [input, setInput] = useState('')
  const [isThinking, setIsThinking] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  // The service owns session ids: chat is POST /copilot/sessions/{id}/chat,
  // and a uuid minted in the browser addresses nothing. The first message
  // opens a session; the rest of the conversation reuses it.
  const sessionRef = useRef<string | null>(null)

  const ensureSession = async (): Promise<string> => {
    if (sessionRef.current) return sessionRef.current
    const session = await api.copilot.createSession(token)
    sessionRef.current = session.id
    return session.id
  }

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isThinking])

  const sendMessage = async (text: string) => {
    if (!text.trim() || isThinking) return

    const userMsg: Message = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date(),
    }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setIsThinking(true)

    try {
      const sessionID = await ensureSession()
      const reply = (await api.copilot.chat(sessionID, text, token)) as CopilotMessage
      setMessages((prev) => [...prev, {
        id: reply.id,
        role: 'assistant',
        content: reply.content,
        timestamp: new Date(reply.created_at),
      }])
    } catch (err) {
      // Say which failure this is. The previous version reported every error
      // as "service unavailable", which is how a 404 on a wrong path went
      // unnoticed: an endpoint that does not exist looked like a service that
      // was merely down.
      const detail = err instanceof ApiError
        ? `**${err.status} ${err.code}** — ${err.message}`
        : `**Unreachable** — ${(err as Error)?.message ?? 'the copilot service did not answer'}`
      setMessages((prev) => [...prev, {
        id: `a-${Date.now()}`,
        role: 'assistant',
        content: detail,
        timestamp: new Date(),
      }])
      // A failed turn must not strand the conversation on a session the
      // service rejected.
      if (err instanceof ApiError && (err.status === 404 || err.status === 410)) {
        sessionRef.current = null
      }
    } finally {
      setIsThinking(false)
    }
  }

  return (
    <div className="flex flex-col space-y-4" style={{ height: 'calc(100vh - 120px)' }}>
      <div>
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-cyan-400" />
          <h1 className="text-xl font-bold text-slate-100">{t('title')}</h1>
        </div>
        <p className="text-sm text-slate-400">{t('subtitle')}</p>
      </div>

      <Card className="flex flex-1 flex-col overflow-hidden">
        <CardContent className="flex flex-1 flex-col overflow-hidden p-0">
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((msg) => (
              <div key={msg.id} className={`flex items-start gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full ${
                  msg.role === 'assistant' ? 'bg-cyan-950 border border-cyan-800' : 'bg-slate-700'
                }`}>
                  {msg.role === 'assistant'
                    ? <Bot className="h-4 w-4 text-cyan-400" />
                    : <User className="h-4 w-4 text-slate-300" />}
                </div>
                <div className={`max-w-2xl rounded-lg px-4 py-3 ${
                  msg.role === 'assistant'
                    ? 'bg-slate-800/60 border border-slate-700/40'
                    : 'bg-cyan-950/60 border border-cyan-800/40'
                }`}>
                  <div className="text-sm text-slate-200 leading-relaxed">{renderContent(msg.content)}</div>
                  <p className="mt-1 text-[10px] text-slate-600">
                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </p>
                </div>
              </div>
            ))}

            {isThinking && (
              <div className="flex items-start gap-3">
                <div className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-cyan-950 border border-cyan-800">
                  <Bot className="h-4 w-4 text-cyan-400" />
                </div>
                <div className="rounded-lg border border-slate-700/40 bg-slate-800/60 px-4 py-3">
                  <p className="mb-1 text-[10px] text-cyan-500">{t('thinking')}</p>
                  <TypingIndicator />
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {messages.length <= 1 && (
            <div className="border-t border-slate-700/40 p-4">
              <p className="mb-2 text-xs font-medium text-slate-500">{t('suggestions')}</p>
              <div className="grid grid-cols-2 gap-2">
                {suggestions.map((key) => (
                  <button key={key} onClick={() => sendMessage(t(key))}
                    className="rounded-md border border-slate-700 bg-slate-800/40 px-3 py-2 text-left text-xs text-slate-300 hover:border-cyan-700 hover:bg-slate-800 hover:text-slate-200 transition-colors">
                    {t(key)}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="border-t border-slate-700/40 p-4">
            <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); sendMessage(input) }}>
              <Input value={input} onChange={(e) => setInput(e.target.value)}
                placeholder={t('placeholder')} className="flex-1 text-xs" disabled={isThinking} />
              <Button type="submit" size="sm" disabled={isThinking || !input.trim()}>
                {isThinking ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                {t('send')}
              </Button>
            </form>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
