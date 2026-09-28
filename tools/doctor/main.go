//go:build linux

// pansou-doctor 是在目标设备（安卓 shell / Termux / 盒子）上直接跑的自检程序。
// 它不依赖 pansou 业务代码，用来把"能不能跑"拆成一条条可观察的判定。
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func line(name string, ok bool, detail string) {
	flag := "FAIL"
	if ok {
		flag = "OK  "
	}
	fmt.Printf("[%s] %-26s %s\n", flag, name, detail)
}

func main() {
	fmt.Printf("== pansou-doctor ==\n")
	fmt.Printf("Go 运行时 : %s  GOOS=%s GOARCH=%s  GOMAXPROCS=%d NumCPU=%d\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), runtime.NumCPU())
	fmt.Printf("指针位宽  : %d 位\n\n", strconv.IntSize)

	// 1. 内存
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err == nil {
		totalMB := si.Totalram / 1024 / 1024
		freeMB := si.Freeram / 1024 / 1024
		fmt.Printf("内存      : 总计 %d MB，空闲 %d MB（建议 GOMEMLIMIT≈空闲的 60%%，即 %dMiB）\n\n",
			totalMB, freeMB, freeMB*60/100)
	} else {
		fmt.Printf("内存      : 读不到（%v）\n\n", err)
	}

	// 2. cgroup 内存配额（pansou 会读这两个文件来设堆软上限）
	for _, p := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		b, err := os.ReadFile(p)
		if err != nil {
			line("cgroup "+p, false, "不存在/不可读（pansou 会保持 Go 默认，无影响）")
			continue
		}
		line("cgroup "+p, true, strings.TrimSpace(string(b)))
	}
	fmt.Println()

	// 3. execmem：sonic 的 JIT 需要"可写且可执行"的匿名内存
	//    安卓的 SELinux 对 untrusted_app / shell 域常常拒绝 execmem，
	//    这一项 FAIL 就说明必须用 no-jit（encoding/json）构建。
	const (
		protRead       = 0x1
		protWrite      = 0x2
		protExec       = 0x4
		mapPrivateAnon = 0x02 | 0x20
		noFD           = ^uintptr(0)
	)
	addr, _, e1 := syscall.Syscall6(syscall.SYS_MMAP, 0, 4096,
		uintptr(protRead|protWrite), uintptr(mapPrivateAnon), noFD, 0)
	if e1 != syscall.Errno(0) {
		line("mmap RW", false, e1.Error())
	} else {
		_, _, e2 := syscall.Syscall6(syscall.SYS_MPROTECT, addr, 4096, uintptr(protRead|protExec), 0, 0, 0)
		if e2 != syscall.Errno(0) {
			line("mprotect RX (execmem)", false,
				e2.Error()+" → sonic JIT 版本在此环境会失败，请用 -nojit 二进制")
		} else {
			line("mprotect RX (execmem)", true, "允许生成可执行内存，JIT 版可用")
		}
		syscall.Syscall6(syscall.SYS_MUNMAP, addr, 4096, 0, 0, 0, 0)
	}

	fmt.Println()

	// 4. DNS：CGO_ENABLED=0 的二进制用 Go 自带解析器，只认 /etc/resolv.conf
	if b, err := os.ReadFile("/etc/resolv.conf"); err != nil {
		line("/etc/resolv.conf", false, err.Error()+" → Go 解析器会退回 127.0.0.1:53，很可能解析失败")
	} else {
		line("/etc/resolv.conf", true, strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", " / "))
	}
	for _, host := range []string{"t.me", "pan.quark.cn", "www.bing.com"} {
		start := time.Now()
		ips, err := net.LookupHost(host)
		if err != nil {
			line("DNS "+host, false, err.Error())
		} else {
			line("DNS "+host, true, fmt.Sprintf("%v (%s)", ips, time.Since(start).Round(time.Millisecond)))
		}
	}
	fmt.Println()

	// 5. t.me 可达性（PanSou 的 TG 来源在国内基本取决于这一项）
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{},
		Proxy:           http.ProxyFromEnvironment,
	}}
	resp, err := client.Get("https://t.me/s/tgsearchers7")
	if err != nil {
		line("HTTPS t.me/s/...", false, err.Error()+" → TG 来源在此网络下拿不到结果，需 PROXY")
	} else {
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		line("HTTPS t.me/s/...", resp.StatusCode == 200,
			fmt.Sprintf("HTTP %d，%d 字节", resp.StatusCode, n))
	}
	px, pset := os.Getenv("HTTPS_PROXY"), "HTTPS_PROXY"
	if px == "" {
		px, pset = os.Getenv("HTTP_PROXY"), "HTTP_PROXY"
	}
	line("代理配置", px != "", fmt.Sprintf("%s=%q", pset, px))
	fmt.Println()

	// 6. 工作目录可写（缓存目录不可写时 pansou 会 log.Fatalf 直接退出）
	cachePath := os.Getenv("CACHE_PATH")
	if cachePath == "" {
		cachePath = "./cache"
	}
	probe := filepath.Join(cachePath, ".doctor-probe")
	if err := os.MkdirAll(filepath.Dir(probe), 0o755); err != nil {
		line("缓存目录可写", false, err.Error())
	} else if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		line("缓存目录可写", false, err.Error())
	} else {
		os.Remove(probe)
		abs, _ := filepath.Abs(cachePath)
		line("缓存目录可写", true, abs)
	}
	// bbolt 那个 db 走硬编码 ./cache，不看 CACHE_PATH
	if err := os.MkdirAll("./cache", 0o755); err != nil {
		line("./cache（check.db 硬编码）", false, err.Error())
	} else {
		wd, _ := filepath.Abs("./cache")
		line("./cache（check.db 硬编码）", true, wd)
	}
	fmt.Println()

	// 7. 监听端口
	port := os.Getenv("PORT")
	if port == "" {
		port = "8888"
	}
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		line("监听 :"+port, false, err.Error())
	} else {
		line("监听 :"+port, true, ln.Addr().String())
		ln.Close()
	}
	fmt.Println()

	// 8. 环境变量一览（只打印与 pansou 相关的）
	keys := []string{"CHANNELS", "ENABLED_PLUGINS", "CONCURRENCY", "OUTBOUND_MAX_CONCURRENCY",
		"HTTP_MAX_CONNS", "ASYNC_MAX_BACKGROUND_WORKERS", "GOMEMLIMIT", "GOGC", "GOMAXPROCS", "CACHE_PATH", "PORT"}
	fmt.Println("== 当前 pansou 相关环境变量 ==")
	for _, k := range keys {
		v, ok := os.LookupEnv(k)
		if ok {
			if len(v) > 70 {
				v = v[:70] + fmt.Sprintf("…(共%d字符)", len(v))
			}
			fmt.Printf("  %-28s = %s\n", k, v)
		} else {
			fmt.Printf("  %-28s = (未设置)\n", k)
		}
	}
	fmt.Println("\n判定参考：上面只要 mmap/mprotect、DNS、缓存目录、监听端口 4 项都 OK，pansou 二进制就能起来。")
}
