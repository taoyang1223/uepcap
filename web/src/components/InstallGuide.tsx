import { ArrowLeft, ExternalLink, Copy, Check, Terminal, Server, Globe, Box, Info } from 'lucide-react'
import { useState } from 'react'

interface InstallGuideProps {
  onBack: () => void
}

const CodeBlock = ({ code, label }: { code: string; label?: string }) => {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="relative group overflow-hidden rounded-xl bg-slate-900 shadow-lg border border-slate-800">
      {label && (
        <div className="flex items-center justify-between px-4 py-2 bg-slate-800/50 border-b border-slate-700/50">
          <span className="text-xs font-medium text-slate-400">{label}</span>
        </div>
      )}
      <div className="relative">
        <pre className="p-4 overflow-x-auto text-sm font-mono text-slate-300 leading-relaxed scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
          <code>{code}</code>
        </pre>
        <button
          onClick={handleCopy}
          className="absolute top-2 right-2 p-2 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white rounded-lg opacity-0 group-hover:opacity-100 transition-all duration-200 shadow-md border border-slate-700"
          title="复制代码"
        >
          {copied ? (
            <Check className="w-4 h-4 text-emerald-400" />
          ) : (
            <Copy className="w-4 h-4" />
          )}
        </button>
      </div>
    </div>
  )
}

const StepCard = ({ number, title, children }: { number: string; title: string; children: React.ReactNode }) => (
  <div className="relative pl-8 md:pl-0">
    <div className="hidden md:flex flex-col items-center absolute -left-4 top-0 bottom-0 w-8">
      <div className="w-8 h-8 rounded-full bg-indigo-600 text-white flex items-center justify-center text-sm font-bold shadow-md z-10 border-2 border-slate-50">
        {number}
      </div>
      <div className="w-0.5 bg-slate-200 flex-1 my-2"></div>
    </div>
    <div className="md:ml-8 bg-white rounded-2xl border border-slate-100 p-6 shadow-sm hover:shadow-md transition-shadow duration-300">
      <div className="flex md:hidden items-center gap-3 mb-4">
        <span className="w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center text-sm font-bold shadow-md">
          {number}
        </span>
        <h3 className="text-lg font-bold text-slate-900">{title}</h3>
      </div>
      <h3 className="hidden md:block text-lg font-bold text-slate-900 mb-4">{title}</h3>
      {children}
    </div>
  </div>
)

export const InstallGuide = ({ onBack }: InstallGuideProps) => {
  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <header className="bg-white/80 border-b border-slate-200 sticky top-0 z-50 backdrop-blur-xl supports-[backdrop-filter]:bg-white/60">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <button
            onClick={onBack}
            className="group flex items-center gap-2 px-3 py-1.5 -ml-3 text-slate-600 hover:text-indigo-600 hover:bg-indigo-50/50 rounded-lg transition-all duration-200"
          >
            <ArrowLeft className="w-5 h-5 transition-transform group-hover:-translate-x-1" />
            <span className="font-medium">返回主页</span>
          </button>
          <div className="text-sm font-medium text-slate-500">v0.1.0</div>
        </div>
      </header>

      {/* Hero Content */}
      <main className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center mb-16 space-y-4">
          <div className="inline-flex items-center justify-center p-2 bg-indigo-50 rounded-2xl mb-4">
            <div className="px-3 py-1 bg-white rounded-xl shadow-sm border border-indigo-100 text-xs font-semibold text-indigo-600 tracking-wide uppercase">
              Deployment Guide
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-extrabold text-slate-900 tracking-tight">
            快速部署 <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-600 to-violet-600">UE PCAP Filter</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-600 max-w-2xl mx-auto leading-relaxed">
            仅需几分钟，即可在本地搭建强大的 PCAP 分析与过滤环境。
          </p>
        </div>

        {/* Project Card */}
        <div className="mb-20 transform hover:scale-[1.01] transition-transform duration-300">
          <div className="relative overflow-hidden bg-gradient-to-br from-indigo-600 to-violet-700 rounded-3xl p-8 md:p-10 text-white shadow-2xl shadow-indigo-200">
            <div className="absolute top-0 right-0 -mt-20 -mr-20 w-80 h-80 bg-white/10 rounded-full blur-3xl"></div>
            <div className="absolute bottom-0 left-0 -mb-20 -ml-20 w-60 h-60 bg-black/10 rounded-full blur-3xl"></div>
            
            <div className="relative z-10 flex flex-col md:flex-row items-center justify-between gap-8">
              <div className="flex items-center gap-6">
                <div className="w-16 h-16 bg-white/10 backdrop-blur-sm rounded-2xl flex items-center justify-center border border-white/20 shadow-inner">
                  <Globe className="w-8 h-8 text-white" />
                </div>
                <div>
                  <h2 className="text-2xl font-bold mb-2">开源项目仓库</h2>
                  <p className="text-indigo-100 text-lg opacity-90">获取源代码、提交 Issue 或贡献代码</p>
                </div>
              </div>
              <a
                href="https://gitee.com/yangdadayyds/uepcap"
                target="_blank"
                rel="noopener noreferrer"
                className="group flex items-center gap-3 bg-white text-indigo-600 px-8 py-4 rounded-xl font-bold shadow-lg hover:shadow-xl hover:bg-indigo-50 transition-all duration-200 whitespace-nowrap"
              >
                <span>访问 Gitee</span>
                <ExternalLink className="w-4 h-4 transition-transform group-hover:translate-x-1 group-hover:-translate-y-1" />
              </a>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
          {/* Left Column: Prerequisites */}
          <div className="lg:col-span-4 space-y-8">
            <div className="sticky top-24">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 bg-amber-100 rounded-xl flex items-center justify-center shadow-sm">
                  <Server className="w-5 h-5 text-amber-600" />
                </div>
                <h2 className="text-2xl font-bold text-slate-900">环境要求</h2>
              </div>
              
              <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-6">
                <div className="space-y-4">
                  {[
                    { name: 'Go 1.21+', desc: '后端编译环境' },
                    { name: 'Node.js 18+', desc: '前端构建环境' },
                    { name: 'tshark', desc: 'PCAP 解析核心' },
                    { name: 'mergecap', desc: '文件合并工具' }
                  ].map((item, i) => (
                    <div key={i} className="flex items-start gap-3 group">
                      <div className="mt-1 w-5 h-5 rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform">
                        <Check className="w-3 h-3 stroke-[3]" />
                      </div>
                      <div>
                        <div className="font-bold text-slate-800">{item.name}</div>
                        <div className="text-sm text-slate-500">{item.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
                
                <div className="pt-6 border-t border-slate-100">
                   <div className="bg-amber-50 rounded-xl p-4 border border-amber-100">
                    <div className="flex gap-3">
                      <Info className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
                      <div className="text-sm text-amber-800 leading-relaxed">
                        请确保 <code className="font-semibold text-amber-900">tshark</code> 和 <code className="font-semibold text-amber-900">mergecap</code> 已添加到系统环境变量中。
                      </div>
                    </div>
                   </div>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Installation Steps */}
          <div className="lg:col-span-8">
            <div className="flex items-center gap-3 mb-8">
              <div className="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center shadow-sm">
                <Terminal className="w-5 h-5 text-indigo-600" />
              </div>
              <h2 className="text-2xl font-bold text-slate-900">安装步骤</h2>
            </div>

            <div className="space-y-8 pb-12 border-l-2 border-slate-100 md:border-l-0 ml-4 md:ml-0 pl-4 md:pl-0">
              <StepCard number="1" title="克隆项目">
                <p className="text-slate-600 mb-4">首先将项目代码克隆到本地目录：</p>
                <CodeBlock label="Terminal" code={`git clone https://gitee.com/yangdadayyds/uepcap.git
cd uepcap`} />
              </StepCard>

              <StepCard number="2" title="安装依赖工具">
                <p className="text-slate-600 mb-4">根据您的操作系统安装 Wireshark 套件：</p>
                <div className="space-y-4">
                  <div>
                    <div className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-slate-400"></span>
                      macOS (Homebrew)
                    </div>
                    <CodeBlock code="brew install wireshark" />
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-slate-400"></span>
                      Ubuntu / Debian
                    </div>
                    <CodeBlock code="sudo apt-get install tshark wireshark-common" />
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-slate-400"></span>
                      CentOS / RHEL
                    </div>
                    <CodeBlock code="sudo yum install wireshark-cli" />
                  </div>
                </div>
              </StepCard>

              <StepCard number="3" title="编译项目">
                <p className="text-slate-600 mb-4">使用 Make 命令一键构建前后端：</p>
                <CodeBlock label="Terminal" code={`# 构建所有组件
make build

# 仅构建前端
make build-web

# 仅构建后端
make build-go`} />
              </StepCard>

              <StepCard number="4" title="启动服务">
                <p className="text-slate-600 mb-4">编译完成后，即可启动服务。开发模式下支持热重载。</p>
                <CodeBlock label="Terminal" code={`# 开发模式运行
make run

# 生产模式运行
./uepcap`} />
                <div className="mt-4 flex items-center gap-2 text-sm bg-slate-50 p-3 rounded-lg text-slate-600 border border-slate-200">
                  <Globe className="w-4 h-4 text-slate-400" />
                  服务默认访问地址：
                  <a href="http://localhost:8080" target="_blank" className="font-mono text-indigo-600 hover:underline">
                    http://localhost:8080
                  </a>
                </div>
              </StepCard>

              <div className="relative pt-8">
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-8 h-8 bg-blue-50 rounded-lg flex items-center justify-center">
                    <Box className="w-4 h-4 text-blue-600" />
                  </div>
                  <h3 className="text-xl font-bold text-slate-900">Docker 部署 (可选)</h3>
                </div>
                <div className="bg-slate-50 rounded-2xl border border-slate-200 p-6">
                  <p className="text-slate-600 mb-4 text-sm">如果您更喜欢使用容器化部署，可以直接使用 Docker：</p>
                  <CodeBlock label="Docker" code={`# 构建镜像
docker build -t uepcap .

# 启动容器
docker run -d -p 8080:8080 --name uepcap uepcap`} />
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white">
        <div className="max-w-5xl mx-auto px-4 py-8 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-slate-500">
            Designed for Network Analysis
          </p>
          <div className="flex items-center gap-6">
            <a href="https://gitee.com/yangdadayyds/uepcap/issues" target="_blank" rel="noopener noreferrer" className="text-sm text-slate-500 hover:text-indigo-600 transition-colors">
              反馈问题
            </a>
            <a href="https://gitee.com/yangdadayyds/uepcap" target="_blank" rel="noopener noreferrer" className="text-sm text-slate-500 hover:text-indigo-600 transition-colors">
              查看源码
            </a>
          </div>
        </div>
      </footer>
    </div>
  )
}
