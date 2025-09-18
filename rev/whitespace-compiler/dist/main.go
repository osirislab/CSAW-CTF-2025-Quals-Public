package main

import (
    "fmt"
    "os"
    "whitespace_compiler/lexer"
    "whitespace_compiler/vm"
)

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"image/color"
	"time"
)

type gameState struct {
  		playerX      float32
		bullets      []bullet
		enemies      []enemy
		gameOver     bool
		playerSpeed  float32
		enemySpeed   float32
		enemyDir     float32
		lastEnemyMove time.Time
}

type bullet struct {
	x, y float32
}

type enemy struct {
	x, y float32
}

const (
	playerWidth  = 40
	playerHeight = 20
	bulletSpeed  = 4.0
	enemyRows    = 2
	enemyCols    = 8
)

func runSpaceInvaders(program string) {
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())
	w := a.NewWindow("Whitespace Invaders")
	w.Resize(fyne.NewSize(800, 600))

	state := &gameState{
		playerX:      400,
		playerSpeed:  8,
		enemySpeed:   2,
		enemyDir:     1,
		lastEnemyMove: time.Now(),
	}

	// Create player
	player := loadAndResizeImage("assets/player.svg", playerWidth, playerHeight)
	
	// Create enemies
	for row := 0; row < enemyRows; row++ {
		for col := 0; col < enemyCols; col++ {
			state.enemies = append(state.enemies, enemy{
				x: float32(100 + col*70),
				y: float32(80 + row*50),
			})
		}
	}

	background := canvas.NewRectangle(color.Black)
	gameContainer := container.NewWithoutLayout()
	gameContainer.Add(background)
	gameContainer.Add(player)
	
	// Size background to window dimensions
	updateBackgroundSize := func(size fyne.Size) {
		background.Resize(size)
		background.Move(fyne.NewPos(0, 0))
	}
	updateBackgroundSize(w.Content().Size())
	gameContainer.Refresh()
	
	// Update background size when window resizes
	// w.SetOnResized(func(size fyne.Size) {
	// 	updateBackgroundSize(size)
	// 	gameContainer.Refresh()
	// })
	
	// Add enemies to container
	for range state.enemies {
		enemyImg := loadAndResizeImage("assets/enemy.svg", 30, 20)
		gameContainer.Add(enemyImg)
	}

	w.SetContent(gameContainer)

	// Game loop
	go func() {
		ticker := time.NewTicker(time.Second / 60)
		defer ticker.Stop()

		for range ticker.C {
			// Check win/lose conditions
			if len(state.enemies) == 0 {
				state.gameOver = true
				showEndScreen(w, true, program)
				return
			}
			// Check if enemies reached bottom
			for _, e := range state.enemies {
				if e.y > 500 {
					state.gameOver = true
					showEndScreen(w, false, program)
					return
				}
			}

			// Update player position
			player.Move(fyne.NewPos(state.playerX-playerWidth/2, 550))

			// Update bullets
			bulletsToRemove := []int{}
			for i := len(state.bullets) - 1; i >= 0; i-- {
				state.bullets[i].y -= bulletSpeed
				if state.bullets[i].y < 0 {
					bulletsToRemove = append(bulletsToRemove, i)
				} else {
					// Update existing bullet position
					bulletIdx := len(gameContainer.Objects) - len(state.bullets) + i
					if bulletIdx >= 0 && bulletIdx < len(gameContainer.Objects) {
						gameContainer.Objects[bulletIdx].Move(fyne.NewPos(
							state.bullets[i].x - 2.5, 
							state.bullets[i].y,
						))
					}
				}
			}
			// Remove bullets in reverse order
			for _, i := range bulletsToRemove {
				state.bullets = append(state.bullets[:i], state.bullets[i+1:]...)
				gameContainer.Remove(gameContainer.Objects[len(gameContainer.Objects)-1])
			}

			// Enemy movement
			if time.Since(state.lastEnemyMove) > 500*time.Millisecond {
				moveDown := false
				for i := range state.enemies {
					state.enemies[i].y += state.enemyDir * state.enemySpeed
					if state.enemies[i].x < 50 || state.enemies[i].x > 750 {
						moveDown = true
					}
				}
				if moveDown {
					state.enemyDir *= -1
					for i := range state.enemies {
						state.enemies[i].y += 20
					}
				}
				state.lastEnemyMove = time.Now()
			}

			// Collision detection
			enemiesToRemove := []int{}
			bulletsToRemove = []int{}
			for i, e := range state.enemies {
				for j, b := range state.bullets {
					// Check if bullet is within enemy bounds (30x20)
					if b.x+2.5 > e.x-15 && 
						b.x-2.5 < e.x+15 &&
						b.y+5 > e.y-10 && 
						b.y-5 < e.y+10 {
						
						enemiesToRemove = append(enemiesToRemove, i)
						bulletsToRemove = append(bulletsToRemove, j)
					}
				}
			}

			// Remove collided enemies and bullets
			for _, i := range reverseUnique(enemiesToRemove) {
				state.enemies = append(state.enemies[:i], state.enemies[i+1:]...)
				gameContainer.Remove(gameContainer.Objects[i+2]) // +2 for background(0) and player(1)
			}
			for _, j := range reverseUnique(bulletsToRemove) {
				state.bullets = append(state.bullets[:j], state.bullets[j+1:]...)
				// Bullets are always at the end of the container objects
				gameContainer.Remove(gameContainer.Objects[len(gameContainer.Objects)-1-j])
			}

			// Update enemies
			fyne.Do(func() {
				for i, e := range state.enemies {
					if i+2 >= len(gameContainer.Objects) { // +2 for background(0) and player(1)
						continue
					}
				obj := gameContainer.Objects[i+2].(*canvas.Image)
				obj.Move(fyne.NewPos(e.x, e.y))
				}
				gameContainer.Refresh()
			})
		}
	}()

	// Keyboard controls
	w.Canvas().SetOnTypedKey(func(e *fyne.KeyEvent) {
		switch e.Name {
		case fyne.KeyLeft, fyne.KeyA:
			state.playerX = max(state.playerX-state.playerSpeed, 0)
		case fyne.KeyRight, fyne.KeyD:
			state.playerX = min(state.playerX+state.playerSpeed, 800)
		case fyne.KeySpace, fyne.KeyW, fyne.KeyUp:
			newBullet := bullet{
				x: state.playerX,
				y: 550 - playerHeight,
			}
			state.bullets = append(state.bullets, newBullet)
			// Create bullet visual
			bulletVisual := canvas.NewRectangle(color.RGBA{R: 255, G: 255, B: 0, A: 255})
			bulletVisual.Resize(fyne.NewSize(5, 10))
			bulletVisual.Move(fyne.NewPos(newBullet.x-2.5, newBullet.y))
			gameContainer.Add(bulletVisual)
		case fyne.KeyS, fyne.KeyDown:
			// Optional: Add downward shooting if needed
		}
	})

	w.ShowAndRun()
}

func max(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}

func min(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}

func showEndScreen(w fyne.Window, won bool, program string) {
    // Show loading screen first
    var progress *widget.ProgressBar
    fyne.Do(func() {
        progress = widget.NewProgressBar()
        loadingContent := container.NewVBox(
            canvas.NewText("Loading your reward...", color.White),
            progress,
        )
        w.SetContent(loadingContent)
    })
        // go func() {
            start := time.Now()
            for i := 0.0; i <= 10.0; i += 1 { // 60 seconds duration (1/600 increments per 100ms)
                time.Sleep(1 * time.Second)
				fyne.Do(func() {
                progress.SetValue(i/10)
				})
                if time.Since(start) >= time.Minute {
                    break
                }
            }
        // }()
    
    
    // Execute synchronously without goroutine
    machine := vm.NewVM()
    err, whitespaceCode := machine.Execute(program)
    if err != nil {
        fmt.Printf("Execution error: %v\n", err)
        os.Exit(1)
    }
	fyne.Do(func() {
		content := container.NewVBox()
		
		if won {
            // Execute only if game not already over (win case)
 
			title := canvas.NewText("Victory!", color.RGBA{G: 200, A: 255})
			title.TextStyle.Bold = true
			title.TextSize = 24
			content.Add(title)

			codeText := canvas.NewText("Whitespace Program:", color.White)
			content.Add(codeText)
			
			codeBox := container.NewScroll(widget.NewLabel(whitespaceCode))
			codeBox.SetMinSize(fyne.NewSize(600, 200))
			content.Add(codeBox)
		} else {
			title := canvas.NewText("Game Over", color.RGBA{R: 200, A: 255})
			title.TextStyle.Bold = true
			title.TextSize = 24
			content.Add(title)
		}

		closeBtn := widget.NewButton("Exit", func() {
			w.Close()
		})
		content.Add(closeBtn)

		w.SetContent(content)
	})
}

func reverseUnique(s []int) []int {
	seen := make(map[int]bool)
	result := []int{}
	for i := len(s)-1; i >= 0; i-- {
		if !seen[s[i]] {
			seen[s[i]] = true
			result = append(result, s[i])
		}
	}
	return result
}

func loadAndResizeImage(path string, width, height float32) *canvas.Image {
	img := canvas.NewImageFromFile(path)
	img.Resize(fyne.NewSize(width, height))
	img.FillMode = canvas.ImageFillStretch
	return img
}

var whitespaceCode string
var program string

func main() {
	// Run game first

	// Check if we should execute the program (only if user won)
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./whitespace <file.ws>")
		os.Exit(1)
	}

	// Read and parse the Whitespace file
	wsFile := os.Args[1]
	program, err := lexer.CleanAndParse(wsFile)
	if err != nil {
		fmt.Printf("Lexer error: %v\n", err)
		os.Exit(1)
	}
    runSpaceInvaders(program)
	
	// Execute only if game not already over (win case)
	// machine := vm.NewVM()
	// if err, whitespaceCode := machine.Execute(program); err != nil {
	// 	fmt.Printf("Execution error: %v\n", err)
	// 	os.Exit(1)
	// }
}
