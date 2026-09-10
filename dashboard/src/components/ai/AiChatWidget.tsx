"use client";

import { useState, useRef, useEffect } from "react";
import { MessageSquare, X, Send, Sparkles, AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export function AiChatWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Initial greeting
  useEffect(() => {
    if (messages.length === 0) {
        setMessages([{ role: "assistant", content: "Hi! I'm PhishTrace AI. I've analyzed this dashboard for you. How can I help today?" }]);
        setSuggestions(["Is this page safe?", "What are the risks?", "Tell me more about PhishTrace"]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSend = async (text: string) => {
    if (!text.trim()) return;

    const userMsg = { role: "user" as const, content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);
    setError(null);

    try {
        const res = await fetch("http://localhost:8005/api/v1/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message: text,
                context: window.location.pathname
            })
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({ detail: res.statusText }));
            throw new Error(errData.detail || `Server Error: ${res.status}`);
        }

        const data = await res.json();
        setMessages((prev) => [...prev, { role: "assistant", content: data.response }]);
        if (data.suggestions) {
            setSuggestions(data.suggestions);
        }

    } catch (error: unknown) {
        const errMessage = error instanceof Error ? error.message : "Connection failed";
        console.error("Chat Error:", error);
        setError(`Connect Error: ${errMessage}`);
        setMessages((prev) => [...prev, { 
            role: "assistant", 
            content: "Sorry, I'm having trouble connecting to my brain. Please ensure the backend is running." 
        }]);
    } finally {
        setIsLoading(false);
    }
  };

  return (
    <div className="fixed bottom-6 left-6 z-[9999] font-sans">
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="mb-4 w-[380px] max-h-[calc(100vh-120px)] h-[min(600px,80vh)] flex flex-col overflow-hidden rounded-[24px] shadow-[0_20px_50px_rgba(0,0,0,0.15)] bg-white border border-slate-100"
          >
            {/* Ultra-Clean Header */}
            <div className="p-5 bg-white border-b border-slate-50 flex justify-between items-center relative overflow-hidden">
               {/* Aesthetic Top Bar */}
               <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-indigo-500 via-purple-500 to-indigo-500" />
               
               <div className="flex items-center gap-3">
                   <div className="w-10 h-10 rounded-xl bg-indigo-50 flex items-center justify-center border border-indigo-100/50 shadow-sm">
                      <Sparkles size={20} className="text-indigo-600" fill="currentColor" />
                   </div>
                   <div>
                       <h3 className="font-bold text-slate-800 text-[15px] leading-tight tracking-tight">PhishTrace AI</h3>
                       <div className="flex items-center gap-1.5">
                           <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                           <p className="text-[11px] text-slate-500 font-semibold uppercase tracking-wider">System Active</p>
                       </div>
                   </div>
               </div>
               <button 
                  onClick={() => setIsOpen(false)}
                  className="w-8 h-8 flex items-center justify-center rounded-full text-slate-400 hover:text-slate-600 hover:bg-slate-50 transition-all"
               >
                   <X size={20} />
               </button>
            </div>

            {/* Error Banner */}
            {error && (
                <div className="bg-rose-50 px-4 py-2.5 text-[11px] text-rose-600 flex items-center gap-2 border-b border-rose-100 animate-in fade-in slide-in-from-top-1">
                    <AlertCircle size={14} className="shrink-0" />
                    <span className="font-medium">{error}</span>
                </div>
            )}

            {/* Messages Area */}
            <div className="flex-1 overflow-y-auto p-5 space-y-6 scroll-smooth bg-[#FBFCFE]">
                {messages.map((m, i) => (
                    <div key={i} className={cn("flex w-full animate-in fade-in slide-in-from-bottom-2 duration-500", m.role === "user" ? "justify-end" : "justify-start")}>
                        <div className={cn(
                            "max-w-[85%] px-5 py-3.5 text-[14px] leading-[1.6] shadow-sm relative",
                            m.role === "user" 
                              ? "bg-slate-900 text-white rounded-[20px] rounded-br-[4px] shadow-indigo-100/20" 
                              : "bg-white text-slate-700 border border-slate-100 rounded-[20px] rounded-bl-[4px] shadow-slate-200/20"
                        )}>
                            <p className="whitespace-pre-wrap">{m.content}</p>
                        </div>
                    </div>
                ))}
                {isLoading && (
                    <div className="flex justify-start animate-in fade-in">
                         <div className="bg-white border border-slate-100 px-5 py-3 rounded-[20px] rounded-bl-[4px] shadow-sm flex items-center gap-3">
                             <div className="flex gap-1.5">
                                {[0,1,2].map(i => (
                                    <motion.div 
                                        key={i}
                                        animate={{ scale: [1, 1.2, 1], opacity: [0.4, 1, 0.4] }} 
                                        transition={{ repeat: Infinity, duration: 0.8, delay: i * 0.2 }} 
                                        className="w-1.5 h-1.5 bg-indigo-500 rounded-full" 
                                    />
                                ))}
                             </div>
                             <span className="text-[12px] text-slate-400 font-medium">Analysing...</span>
                         </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* Suggestions */}
            {suggestions.length > 0 && !isLoading && (
                <div className="px-4 py-3 bg-white border-t border-slate-50 flex gap-2 overflow-x-auto no-scrollbar scroll-smooth">
                    {suggestions.map((s, i) => (
                        <button 
                           key={i} 
                           onClick={() => handleSend(s)}
                           className="whitespace-nowrap px-4 py-2 bg-white border border-slate-200 text-slate-600 text-[12px] font-semibold rounded-full hover:border-indigo-400 hover:text-indigo-600 hover:bg-indigo-50 transition-all active:scale-95 shadow-sm"
                        >
                            {s}
                        </button>
                    ))}
                </div>
            )}

            {/* Input Area */}
            <div className="p-5 bg-white border-t border-slate-100">
                <form 
                    onSubmit={(e) => { e.preventDefault(); handleSend(input); }}
                    className="flex gap-2 items-center bg-slate-50 p-1.5 rounded-full border border-slate-200 focus-within:ring-2 focus-within:ring-indigo-100 focus-within:border-indigo-200 transition-all shadow-inner"
                >
                    <input
                        className="flex-1 bg-transparent px-4 text-sm outline-none text-slate-800 placeholder:text-slate-400 font-medium"
                        placeholder="Ask me anything..."
                        value={input}
                        onChange={(e) => setInput(e.target.value)} 
                    />
                    <button 
                        type="submit" 
                        disabled={isLoading || !input.trim()} 
                        className={cn(
                            "h-9 w-9 rounded-full shadow-md flex items-center justify-center transition-all shrink-0", 
                            isLoading ? "bg-slate-200 text-slate-400" : "bg-indigo-600 text-white hover:bg-indigo-700 hover:scale-105 active:scale-95"
                        )}
                    >
                        <Send size={16} className="ml-0.5" />
                    </button>
                </form>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Floating Button */}
      <motion.button
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
            "w-16 h-16 rounded-full shadow-[0_10px_30px_rgba(79,70,229,0.3)] flex items-center justify-center transition-all duration-300 relative group z-[9999]",
            isOpen 
                ? "bg-white text-slate-800 border border-slate-100 ring-4 ring-slate-50" 
                : "bg-indigo-600 text-white hover:bg-indigo-700"
        )}
      >
        {isOpen ? (
            <X size={28} />
        ) : (
             <div className="relative">
                <MessageSquare size={30} fill="currentColor" strokeWidth={0} />
                <motion.div 
                    animate={{ scale: [1, 1.2, 1] }} 
                    transition={{ repeat: Infinity, duration: 2 }}
                    className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-rose-500 rounded-full border-[3px] border-indigo-600"
                />
             </div>
        )}
      </motion.button>
      
      {/* Tooltip */}
      {!isOpen && (
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="absolute left-[80px] bottom-4 bg-white px-4 py-2.5 rounded-2xl shadow-[0_10px_25px_rgba(0,0,0,0.1)] border border-slate-100 text-[13px] font-bold text-slate-800 whitespace-nowrap flex items-center gap-2 pointer-events-none"
          >
              <Sparkles size={14} className="text-indigo-500" fill="currentColor" />
              Ask PhishTrace AI
              {/* Triangle */}
              <div className="absolute left-[-6px] top-1/2 -translate-y-1/2 w-3 h-3 bg-white border-l border-b border-slate-100 rotate-45" />
          </motion.div>
      )}
    </div>
  );
}
